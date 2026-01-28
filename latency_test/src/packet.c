/**
 * @file packet.c
 * @brief HW Timestamp Latency Test - Packet Building Implementation
 *
 * DPDK formatı ile uyumlu paket oluşturma
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "packet.h"
#include "config.h"
#include "common.h"

// ============================================
// CHECKSUM CALCULATION
// ============================================

/**
 * IP header checksum hesapla
 */
static uint16_t ip_checksum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(const uint8_t *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

// ============================================
// PACKET BUILDING
// ============================================

int build_test_packet(uint8_t *buffer,
                      size_t packet_size,
                      uint16_t vlan_id,
                      uint16_t vl_id,
                      uint64_t seq_num) {

    if (packet_size < TOTAL_HDR_SIZE + SEQ_NUM_SIZE) {
        LOG_ERROR("Packet size too small: %zu < %d",
                 packet_size, TOTAL_HDR_SIZE + SEQ_NUM_SIZE);
        return -1;
    }

    if (packet_size > MAX_PACKET_SIZE) {
        LOG_WARN("Packet size clamped: %zu -> %d", packet_size, MAX_PACKET_SIZE);
        packet_size = MAX_PACKET_SIZE;
    }

    memset(buffer, 0, packet_size);

    struct packet_hdr *hdr = (struct packet_hdr *)buffer;

    // ---- Ethernet Header ----
    // DST MAC: 03:00:00:00:VV:VV (VV = VL-ID)
    hdr->eth.dst_mac[0] = g_dst_mac_prefix[0];
    hdr->eth.dst_mac[1] = g_dst_mac_prefix[1];
    hdr->eth.dst_mac[2] = g_dst_mac_prefix[2];
    hdr->eth.dst_mac[3] = g_dst_mac_prefix[3];
    hdr->eth.dst_mac[4] = (vl_id >> 8) & 0xFF;
    hdr->eth.dst_mac[5] = vl_id & 0xFF;

    // SRC MAC: 02:00:00:00:00:20
    memcpy(hdr->eth.src_mac, g_src_mac, ETH_ALEN);

    // EtherType: 802.1Q VLAN
    hdr->eth.ether_type = htons(ETH_P_8021Q);

    // ---- VLAN Header ----
    // TCI: Priority(0) + DEI(0) + VLAN ID
    hdr->vlan.tci = htons(vlan_id & 0x0FFF);
    // Next protocol: IP
    hdr->vlan.next_proto = htons(ETH_P_IP);

    // ---- IP Header ----
    hdr->ip.version_ihl = (PKT_IP_VERSION << 4) | PKT_IP_IHL;
    hdr->ip.tos = PKT_IP_TOS;
    hdr->ip.total_len = htons((uint16_t)(packet_size - ETH_HDR_SIZE - VLAN_HDR_SIZE));
    hdr->ip.id = htons((uint16_t)(seq_num & 0xFFFF));
    hdr->ip.frag_off = 0;
    hdr->ip.ttl = PKT_IP_TTL;
    hdr->ip.protocol = PKT_IP_PROTOCOL_UDP;
    hdr->ip.checksum = 0;  // Hesaplanacak

    // SRC IP: 10.0.0.0
    hdr->ip.src_ip = htonl(SRC_IP_ADDR);

    // DST IP: 224.224.VV.VV (VV = VL-ID)
    hdr->ip.dst_ip = htonl(DST_IP_PREFIX | vl_id);

    // IP checksum
    hdr->ip.checksum = ip_checksum(&hdr->ip, IP_HDR_SIZE);

    // ---- UDP Header ----
    hdr->udp.src_port = htons(UDP_SRC_PORT);
    hdr->udp.dst_port = htons(UDP_DST_PORT);
    hdr->udp.length = htons((uint16_t)(packet_size - ETH_HDR_SIZE - VLAN_HDR_SIZE - IP_HDR_SIZE));
    hdr->udp.checksum = 0;  // UDP checksum opsiyonel

    // ---- Payload ----
    uint8_t *payload = buffer + TOTAL_HDR_SIZE;
    size_t payload_len = packet_size - TOTAL_HDR_SIZE;

    // Sequence number (first 8 bytes)
    uint64_t seq_be = htobe64(seq_num);
    memcpy(payload, &seq_be, sizeof(seq_be));

    // Fill rest with pattern (optional, for debugging)
    for (size_t i = SEQ_NUM_SIZE; i < payload_len; i++) {
        payload[i] = (uint8_t)(i & 0xFF);
    }

    LOG_TRACE("Built packet: VLAN=%u, VL-ID=%u, seq=%lu, size=%zu",
             vlan_id, vl_id, seq_num, packet_size);

    return (int)packet_size;
}

// ============================================
// PACKET PARSING
// ============================================

uint16_t extract_vlan_id(const uint8_t *packet, size_t packet_len) {
    if (packet_len < ETH_HDR_SIZE + VLAN_HDR_SIZE) {
        LOG_TRACE("Packet too short for VLAN: %zu bytes", packet_len);
        return 0;
    }

    const struct eth_hdr *eth = (const struct eth_hdr *)packet;

    // Check if VLAN tagged
    if (ntohs(eth->ether_type) != ETH_P_8021Q) {
        LOG_TRACE("Not a VLAN packet: ether_type=0x%04x", ntohs(eth->ether_type));
        return 0;
    }

    const struct vlan_hdr *vlan = (const struct vlan_hdr *)(packet + ETH_HDR_SIZE);
    uint16_t tci = ntohs(vlan->tci);
    uint16_t vlan_id = tci & 0x0FFF;

    return vlan_id;
}

uint16_t extract_vl_id(const uint8_t *packet, size_t packet_len) {
    if (packet_len < ETH_HDR_SIZE) {
        return 0;
    }

    const struct eth_hdr *eth = (const struct eth_hdr *)packet;

    // VL-ID is in DST MAC last 2 bytes: 03:00:00:00:XX:XX
    uint16_t vl_id = ((uint16_t)eth->dst_mac[4] << 8) | eth->dst_mac[5];

    return vl_id;
}

uint64_t extract_seq_num(const uint8_t *packet, size_t packet_len) {
    // Check if packet has VLAN tag
    const struct eth_hdr *eth = (const struct eth_hdr *)packet;
    bool has_vlan = (ntohs(eth->ether_type) == ETH_P_8021Q);

    size_t hdr_size = has_vlan ? TOTAL_HDR_SIZE : TOTAL_HDR_SIZE_UNTAGGED;

    if (packet_len < hdr_size + SEQ_NUM_SIZE) {
        LOG_TRACE("Packet too short for seq_num: %zu bytes (need %zu)", packet_len, hdr_size + SEQ_NUM_SIZE);
        return 0;
    }

    const uint8_t *payload = packet + hdr_size;
    uint64_t seq_be;
    memcpy(&seq_be, payload, sizeof(seq_be));

    return be64toh(seq_be);
}

bool is_our_test_packet(const uint8_t *packet,
                        size_t packet_len,
                        uint16_t expected_vlan,
                        uint16_t expected_vlid) {

    // Check if packet has VLAN tag or is untagged
    const struct eth_hdr *eth = (const struct eth_hdr *)packet;
    bool has_vlan = (ntohs(eth->ether_type) == ETH_P_8021Q);

    size_t min_len = has_vlan ? TOTAL_HDR_SIZE : TOTAL_HDR_SIZE_UNTAGGED;
    if (packet_len < min_len) {
        return false;
    }

    // Check DST MAC prefix: 03:00:00:00:XX:XX
    if (eth->dst_mac[0] != g_dst_mac_prefix[0] ||
        eth->dst_mac[1] != g_dst_mac_prefix[1] ||
        eth->dst_mac[2] != g_dst_mac_prefix[2] ||
        eth->dst_mac[3] != g_dst_mac_prefix[3]) {
        LOG_TRACE("DST MAC prefix mismatch: %02x:%02x:%02x:%02x",
                 eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2], eth->dst_mac[3]);
        return false;
    }

    // Check VL-ID (from DST MAC, always present)
    if (expected_vlid != 0) {
        uint16_t vl_id = extract_vl_id(packet, packet_len);
        if (vl_id != expected_vlid) {
            LOG_TRACE("VL-ID mismatch: expected=%u, got=%u", expected_vlid, vl_id);
            return false;
        }
    }

    // Check VLAN ID if specified AND packet has VLAN tag
    if (expected_vlan != 0 && has_vlan) {
        uint16_t vlan_id = extract_vlan_id(packet, packet_len);
        if (vlan_id != expected_vlan) {
            LOG_TRACE("VLAN mismatch: expected=%u, got=%u", expected_vlan, vlan_id);
            return false;
        }
    }

    // If packet is untagged (VLAN stripped by switch), that's OK
    // We match by VL-ID and sequence number instead
    if (!has_vlan) {
        LOG_TRACE("Packet is untagged (VLAN stripped by switch), matching by VL-ID");
    }

    return true;
}

void print_packet_info(const uint8_t *packet, size_t packet_len) {
    if (packet_len < TOTAL_HDR_SIZE) {
        printf("Packet too short: %zu bytes\n", packet_len);
        return;
    }

    const struct packet_hdr *hdr = (const struct packet_hdr *)packet;

    printf("=== Packet Info (%zu bytes) ===\n", packet_len);

    // Ethernet
    printf("ETH: DST=%02x:%02x:%02x:%02x:%02x:%02x SRC=%02x:%02x:%02x:%02x:%02x:%02x Type=0x%04x\n",
           hdr->eth.dst_mac[0], hdr->eth.dst_mac[1], hdr->eth.dst_mac[2],
           hdr->eth.dst_mac[3], hdr->eth.dst_mac[4], hdr->eth.dst_mac[5],
           hdr->eth.src_mac[0], hdr->eth.src_mac[1], hdr->eth.src_mac[2],
           hdr->eth.src_mac[3], hdr->eth.src_mac[4], hdr->eth.src_mac[5],
           ntohs(hdr->eth.ether_type));

    // VLAN
    uint16_t vlan_id = ntohs(hdr->vlan.tci) & 0x0FFF;
    printf("VLAN: ID=%u Priority=%u\n", vlan_id, (ntohs(hdr->vlan.tci) >> 13) & 0x7);

    // IP
    uint32_t src_ip = ntohl(hdr->ip.src_ip);
    uint32_t dst_ip = ntohl(hdr->ip.dst_ip);
    printf("IP: SRC=%u.%u.%u.%u DST=%u.%u.%u.%u TTL=%u Proto=%u\n",
           (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
           (src_ip >> 8) & 0xFF, src_ip & 0xFF,
           (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
           (dst_ip >> 8) & 0xFF, dst_ip & 0xFF,
           hdr->ip.ttl, hdr->ip.protocol);

    // UDP
    printf("UDP: SRC=%u DST=%u Len=%u\n",
           ntohs(hdr->udp.src_port), ntohs(hdr->udp.dst_port),
           ntohs(hdr->udp.length));

    // Payload (seq num)
    if (packet_len >= TOTAL_HDR_SIZE + SEQ_NUM_SIZE) {
        uint64_t seq = extract_seq_num(packet, packet_len);
        printf("Payload: SeqNum=%lu\n", seq);
    }

    // VL-ID
    uint16_t vl_id = extract_vl_id(packet, packet_len);
    printf("VL-ID: %u (0x%04x)\n", vl_id, vl_id);

    printf("==============================\n");
}

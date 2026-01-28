/**
 * @file packet.h
 * @brief HW Timestamp Latency Test - Packet Building API
 *
 * DPDK formatı ile uyumlu paket oluşturma
 * Format: ETH + VLAN(802.1Q) + IP + UDP + Payload
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>

#include "common.h"

// ============================================
// PACKET STRUCTURES
// ============================================

// Ethernet header (14 bytes)
struct __attribute__((packed)) eth_hdr {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
};

// VLAN header (4 bytes) - 802.1Q
// Note: TPID (0x8100) is in eth_hdr.ether_type
// This struct contains only the fields AFTER the TPID
struct __attribute__((packed)) vlan_hdr {
    uint16_t tci;           // Tag Control Info: PRI(3) + DEI(1) + VID(12)
    uint16_t next_proto;    // Next protocol EtherType (0x0800 for IP)
};

// IPv4 header (20 bytes, no options)
struct __attribute__((packed)) ip_hdr {
    uint8_t  version_ihl;   // Version (4) + IHL (5)
    uint8_t  tos;           // Type of Service
    uint16_t total_len;     // Total Length
    uint16_t id;            // Identification
    uint16_t frag_off;      // Fragment Offset
    uint8_t  ttl;           // Time to Live
    uint8_t  protocol;      // Protocol (17 = UDP)
    uint16_t checksum;      // Header Checksum
    uint32_t src_ip;        // Source IP
    uint32_t dst_ip;        // Destination IP
};

// UDP header (8 bytes)
struct __attribute__((packed)) udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

// Complete packet header (46 bytes)
struct __attribute__((packed)) packet_hdr {
    struct eth_hdr  eth;
    struct vlan_hdr vlan;
    struct ip_hdr   ip;
    struct udp_hdr  udp;
};

// ============================================
// FUNCTION DECLARATIONS
// ============================================

/**
 * Test paketi oluştur
 *
 * @param buffer        Paket buffer (en az packet_size bytes)
 * @param packet_size   Toplam paket boyutu
 * @param vlan_id       VLAN ID (802.1Q tag)
 * @param vl_id         VL-ID (DST MAC/IP son 2 byte)
 * @param seq_num       Sequence number
 * @return              Oluşturulan paket boyutu, hata durumunda <0
 */
int build_test_packet(uint8_t *buffer,
                      size_t packet_size,
                      uint16_t vlan_id,
                      uint16_t vl_id,
                      uint64_t seq_num);

/**
 * Alınan paketten VLAN ID çıkar
 *
 * @param packet        Paket verisi
 * @param packet_len    Paket uzunluğu
 * @return              VLAN ID, hata durumunda 0
 */
uint16_t extract_vlan_id(const uint8_t *packet, size_t packet_len);

/**
 * Alınan paketten VL-ID çıkar (DST MAC son 2 byte)
 *
 * @param packet        Paket verisi
 * @param packet_len    Paket uzunluğu
 * @return              VL-ID, hata durumunda 0
 */
uint16_t extract_vl_id(const uint8_t *packet, size_t packet_len);

/**
 * Alınan paketten sequence number çıkar
 *
 * @param packet        Paket verisi
 * @param packet_len    Paket uzunluğu
 * @return              Sequence number, hata durumunda 0
 */
uint64_t extract_seq_num(const uint8_t *packet, size_t packet_len);

/**
 * Paketin bizim test paketimiz olup olmadığını kontrol et
 *
 * @param packet        Paket verisi
 * @param packet_len    Paket uzunluğu
 * @param expected_vlan Beklenen VLAN ID (0 = kontrol etme)
 * @param expected_vlid Beklenen VL-ID (0 = kontrol etme)
 * @return              true = bizim paketimiz, false = değil
 */
bool is_our_test_packet(const uint8_t *packet,
                        size_t packet_len,
                        uint16_t expected_vlan,
                        uint16_t expected_vlid);

/**
 * Paket bilgilerini yazdır (debug için)
 *
 * @param packet        Paket verisi
 * @param packet_len    Paket uzunluğu
 */
void print_packet_info(const uint8_t *packet, size_t packet_len);

#endif // PACKET_H

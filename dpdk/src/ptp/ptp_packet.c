#define _GNU_SOURCE  // For clock_gettime and CLOCK_REALTIME

/**
 * PTP Packet Processing
 *
 * Handles parsing of received PTP packets and building of Delay_Req packets.
 * Supports Layer 2 (Ethernet) transport with VLAN tagging.
 */

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <string.h>
#include <time.h>

#include "ptp_types.h"
#include "ptp_slave.h"
#include "config.h"

// Helper: Get current time in nanoseconds (CLOCK_REALTIME - same epoch as PTP)
static inline uint64_t get_realtime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// VLAN header structure
struct vlan_hdr {
    uint16_t vlan_tci;      // Priority (3) + CFI (1) + VLAN ID (12)
    uint16_t eth_proto;     // Inner EtherType
} __attribute__((packed));

// Full Ethernet + VLAN + PTP header structure for parsing
struct ptp_eth_frame {
    struct rte_ether_hdr eth;
    struct vlan_hdr vlan;
    // PTP header follows
} __attribute__((packed));

// PTP destination MAC base (last 2 bytes = VL-IDX, big-endian)
// Format: 03:00:00:00:VL_H:VL_L
#define PTP_DST_MAC_BASE_0  0x03
#define PTP_DST_MAC_BASE_1  0x00
#define PTP_DST_MAC_BASE_2  0x00
#define PTP_DST_MAC_BASE_3  0x00

// PTP source MAC (fixed for all PTP packets)
// Format: 02:00:00:00:00:20
static const uint8_t ptp_src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x20};

/**
 * Check if mbuf contains a PTP packet (EtherType 0x88F7)
 */
bool ptp_is_ptp_packet(struct rte_mbuf *mbuf)
{
    if (rte_pktmbuf_data_len(mbuf) < sizeof(struct rte_ether_hdr))
        return false;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    // Check for direct PTP EtherType
    if (ether_type == PTP_ETHERTYPE)
        return true;

    // Check for VLAN-tagged PTP
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        if (rte_pktmbuf_data_len(mbuf) < sizeof(struct ptp_eth_frame))
            return false;

        struct ptp_eth_frame *frame = rte_pktmbuf_mtod(mbuf, struct ptp_eth_frame *);
        uint16_t inner_type = rte_be_to_cpu_16(frame->vlan.eth_proto);
        return inner_type == PTP_ETHERTYPE;
    }

    return false;
}

/**
 * Get PTP message type from packet
 */
int ptp_get_msg_type(struct rte_mbuf *mbuf)
{
    uint8_t *ptp_data;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    if (ether_type == PTP_ETHERTYPE) {
        // Untagged
        ptp_data = rte_pktmbuf_mtod_offset(mbuf, uint8_t *,
                                           sizeof(struct rte_ether_hdr));
    } else if (ether_type == RTE_ETHER_TYPE_VLAN) {
        // VLAN tagged
        ptp_data = rte_pktmbuf_mtod_offset(mbuf, uint8_t *,
                                           sizeof(struct ptp_eth_frame));
    } else {
        return -1;
    }

    // First byte: transport (4 bits) + message type (4 bits)
    return ptp_data[0] & 0x0F;
}

/**
 * Get VLAN ID from packet
 */
uint16_t ptp_get_vlan_id(struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        struct ptp_eth_frame *frame = rte_pktmbuf_mtod(mbuf, struct ptp_eth_frame *);
        return rte_be_to_cpu_16(frame->vlan.vlan_tci) & 0x0FFF;
    }

    return 0; // Untagged
}

/**
 * Get pointer to PTP header in mbuf
 */
static ptp_header_t *get_ptp_header(struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    if (ether_type == PTP_ETHERTYPE) {
        return rte_pktmbuf_mtod_offset(mbuf, ptp_header_t *,
                                       sizeof(struct rte_ether_hdr));
    } else if (ether_type == RTE_ETHER_TYPE_VLAN) {
        return rte_pktmbuf_mtod_offset(mbuf, ptp_header_t *,
                                       sizeof(struct ptp_eth_frame));
    }

    return NULL;
}

/**
 * Parse received PTP packet and update session state
 */
int ptp_packet_process(ptp_session_t *session,
                       struct rte_mbuf *mbuf,
                       uint64_t rx_tsc)
{
    if (!session || !mbuf)
        return -1;

    if (!ptp_is_ptp_packet(mbuf))
        return -1;

    int msg_type = ptp_get_msg_type(mbuf);
    if (msg_type < 0)
        return -1;

    uint16_t vlan_id = ptp_get_vlan_id(mbuf);

    // Verify VLAN matches session's RX VLAN
    if (vlan_id != session->rx_vlan_id) {
        return -2; // VLAN mismatch
    }

    ptp_header_t *hdr = get_ptp_header(mbuf);
    if (!hdr)
        return -1;

    switch (msg_type) {
    case PTP_MSG_SYNC: {
        // Sync message: extract t1 (origin timestamp)
        ptp_sync_msg_t *sync = (ptp_sync_msg_t *)hdr;

        // Debug: Print received Sync packet details (first 10 only)
        static uint64_t sync_print_count = 0;
        if (sync_print_count < 10) {
            uint64_t t1_seconds = rte_be_to_cpu_32(sync->origin_timestamp.seconds_lsb);
            uint32_t t1_nanos = rte_be_to_cpu_32(sync->origin_timestamp.nanoseconds);
            uint64_t t1_ns = t1_seconds * 1000000000ULL + t1_nanos;
            printf("PTP RX Sync [VLAN=%u]: SeqID=%u\n", vlan_id, rte_be_to_cpu_16(hdr->sequence_id));
            printf("  T1 (from DTN) = %lu.%09u sec = %lu ns\n", t1_seconds, t1_nanos, t1_ns);
            printf("  T2 (our TSC)  = %lu cycles\n", rx_tsc);
            sync_print_count++;
        }

        ptp_handle_sync(session, hdr, &sync->origin_timestamp, rx_tsc);
        session->sync_rx_count++;
        break;
    }

    case PTP_MSG_DELAY_RESP: {
        // Delay_Resp message: extract t4 (receive timestamp)
        ptp_delay_resp_msg_t *resp = (ptp_delay_resp_msg_t *)hdr;

        // Debug: Print received Delay_Resp packet details (first 10 only)
        static uint64_t resp_print_count = 0;
        if (resp_print_count < 10) {
            uint64_t t4_seconds = rte_be_to_cpu_32(resp->receive_timestamp.seconds_lsb);
            uint32_t t4_nanos = rte_be_to_cpu_32(resp->receive_timestamp.nanoseconds);
            uint64_t t4_ns = t4_seconds * 1000000000ULL + t4_nanos;
            printf("PTP RX Delay_Resp [VLAN=%u]: SeqID=%u\n", vlan_id, rte_be_to_cpu_16(hdr->sequence_id));
            printf("  T4 (from DTN) = %lu.%09u sec = %lu ns%s\n",
                   t4_seconds, t4_nanos, t4_ns,
                   (t4_seconds == 0 && t4_nanos == 0) ? " (EMPTY!)" : "");
            resp_print_count++;
        }

        // NOTE: DTN is non-standard and sends requesting_port_id as all zeros
        // We rely on VLAN matching (done above) and SeqID matching (done in ptp_handle_delay_resp)
        // for correct session identification. Port identity check is skipped.
        // Debug: Print requesting port identity (first 5 only)
        static uint64_t port_id_print_count = 0;
        if (port_id_print_count < 5) {
            printf("PTP Delay_Resp [VLAN=%u]: requesting_port_id=%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X port=%u%s\n",
                   vlan_id,
                   resp->requesting_port_id.clock_identity[0],
                   resp->requesting_port_id.clock_identity[1],
                   resp->requesting_port_id.clock_identity[2],
                   resp->requesting_port_id.clock_identity[3],
                   resp->requesting_port_id.clock_identity[4],
                   resp->requesting_port_id.clock_identity[5],
                   resp->requesting_port_id.clock_identity[6],
                   resp->requesting_port_id.clock_identity[7],
                   rte_be_to_cpu_16(resp->requesting_port_id.port_number),
                   " (DTN non-standard, check skipped)");
            port_id_print_count++;
        }

        ptp_handle_delay_resp(session, hdr, &resp->receive_timestamp,
                             &resp->requesting_port_id);
        session->delay_resp_rx_count++;
        break;
    }

    case PTP_MSG_FOLLOW_UP:
        // One-step mode: we don't expect Follow_Up, ignore
        break;

    case PTP_MSG_ANNOUNCE:
        // Announce message: can be used to learn master info
        // For now, we just ignore it
        break;

    default:
        // Unknown or unsupported message type
        return -4;
    }

    return 0;
}

/**
 * Build and send Delay_Req packet
 * Note: Uses session->tx_port_id for transmission (split TX/RX port support)
 *       The port parameter is used for mbuf pool access only
 */
int ptp_send_delay_req(ptp_session_t *session,
                       ptp_port_t *port,
                       uint64_t *tx_tsc)
{
    if (!session || !port || !port->tx_mbuf_pool)
        return -1;

    // Use session's TX port for transmission
    uint16_t tx_port_id = session->tx_port_id;

    // Allocate mbuf
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(port->tx_mbuf_pool);
    if (!mbuf)
        return -2;

    // PTP message length (matching Wireshark capture: 106 bytes)
    // Standard Delay_Req is 44 bytes, DTN uses 106 bytes with padding
    #define PTP_MSG_LENGTH_PADDED  106

    // Calculate total packet size
    size_t pkt_size = sizeof(struct rte_ether_hdr) +
                      sizeof(struct vlan_hdr) +
                      PTP_MSG_LENGTH_PADDED;  // 106 bytes to match DTN format

    // Reserve headroom and get data pointer
    char *data = rte_pktmbuf_append(mbuf, pkt_size);
    if (!data) {
        rte_pktmbuf_free(mbuf);
        return -3;
    }

    // Build Ethernet header
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;

    // Build Dst MAC: 03:00:00:00:VL_H:VL_L (VL-IDX in last 2 bytes, big-endian)
    eth->dst_addr.addr_bytes[0] = PTP_DST_MAC_BASE_0;
    eth->dst_addr.addr_bytes[1] = PTP_DST_MAC_BASE_1;
    eth->dst_addr.addr_bytes[2] = PTP_DST_MAC_BASE_2;
    eth->dst_addr.addr_bytes[3] = PTP_DST_MAC_BASE_3;
    eth->dst_addr.addr_bytes[4] = (session->tx_vl_idx >> 8) & 0xFF;  // VL-IDX high byte
    eth->dst_addr.addr_bytes[5] = session->tx_vl_idx & 0xFF;         // VL-IDX low byte

    // Use fixed PTP source MAC: 02:00:00:00:00:20
    memcpy(eth->src_addr.addr_bytes, ptp_src_mac, 6);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);

    // Build VLAN header
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    vlan->vlan_tci = rte_cpu_to_be_16(session->tx_vlan_id & 0x0FFF);
    vlan->eth_proto = rte_cpu_to_be_16(PTP_ETHERTYPE);

    // Build PTP Delay_Req header (matching Wireshark capture format exactly)
    // Zero entire PTP payload first (106 bytes with padding)
    uint8_t *ptp_start = (uint8_t *)(vlan + 1);
    memset(ptp_start, 0, PTP_MSG_LENGTH_PADDED);

    ptp_sync_msg_t *delay_req = (ptp_sync_msg_t *)ptp_start;

    delay_req->header.msg_type = PTP_MSG_DELAY_REQ;   // 0x01
    delay_req->header.transport = 0;                  // Layer 2
    delay_req->header.version = PTP_VERSION;          // 2
    delay_req->header.msg_length = rte_cpu_to_be_16(PTP_MSG_LENGTH_PADDED);  // 106 (0x006a)
    delay_req->header.domain_number = PTP_DEFAULT_DOMAIN;  // 10
    delay_req->header.flags = rte_cpu_to_be_16(0x0102);    // Match Wireshark capture
    delay_req->header.correction = 0;
    delay_req->header.sequence_id = rte_cpu_to_be_16(session->delay_req_seq_id);
    delay_req->header.control = PTP_CTRL_DELAY_REQ;   // 1
    delay_req->header.log_msg_interval = PTP_LOG_DELAY_REQ_INT;  // -1

    // Copy our port identity
    memcpy(&delay_req->header.source_port_id, &session->our_port_id,
           sizeof(ptp_port_identity_t));

    // Origin timestamp is set to 0 (we use software timestamp)
    memset(&delay_req->origin_timestamp, 0, sizeof(ptp_timestamp_t));

    // Set mbuf metadata
    mbuf->l2_len = sizeof(struct rte_ether_hdr) + sizeof(struct vlan_hdr);
    mbuf->ol_flags = RTE_MBUF_F_TX_VLAN;
    mbuf->vlan_tci = session->tx_vlan_id;

    // Record TX timestamp (TSC) just before sending
    uint64_t tsc_before = rte_rdtsc();

    // Send packet via TX port (may differ from RX port)
    uint16_t nb_tx = rte_eth_tx_burst(tx_port_id, PTP_TX_QUEUE_ID, &mbuf, 1);

    // Record TX timestamp (TSC) just after sending
    uint64_t tsc_after = rte_rdtsc();

    if (nb_tx != 1) {
        rte_pktmbuf_free(mbuf);
        return -4;
    }

    // Use average of before/after as TX timestamp
    *tx_tsc = (tsc_before + tsc_after) / 2;

    // Update session
    session->t3_tsc = *tx_tsc;
    session->t3_realtime_ns = get_realtime_ns();  // Realtime for offset calculation
    session->last_delay_req_seq_id = session->delay_req_seq_id;  // Store before incrementing
    session->delay_req_seq_id++;
    session->delay_req_tx_count++;
    session->last_delay_req_tsc = *tx_tsc;

    // Debug: Print sent Delay_Req packet in raw hex dump format
    static uint64_t delay_req_print_count = 0;
    if (delay_req_print_count < 10) {
        printf("PTP TX Delay_Req [TXPort%u VLAN%u] (RXPort%u): SeqID=%u VL-IDX=%u T3=%lu cycles\n",
               tx_port_id, session->tx_vlan_id, session->port_id,
               rte_be_to_cpu_16(delay_req->header.sequence_id),
               session->tx_vl_idx, *tx_tsc);
        printf("  Raw packet (%zu bytes):\n", pkt_size);
        uint8_t *pkt = (uint8_t *)data;
        for (size_t i = 0; i < pkt_size; i += 16) {
            printf("  %04zx: ", i);
            // Hex bytes
            for (size_t j = 0; j < 16 && (i + j) < pkt_size; j++) {
                printf("%02x ", pkt[i + j]);
            }
            // Padding for incomplete lines
            for (size_t j = pkt_size - i; j < 16 && (i + j) >= pkt_size; j++) {
                printf("   ");
            }
            // ASCII representation
            printf(" |");
            for (size_t j = 0; j < 16 && (i + j) < pkt_size; j++) {
                uint8_t c = pkt[i + j];
                printf("%c", (c >= 32 && c < 127) ? c : '.');
            }
            printf("|\n");
        }
        delay_req_print_count++;
    }

    return 0;
}

/**
 * Initialize session's port identity
 * NOTE: DTN uses a non-standard format. The requesting_port_id in Delay_Resp
 * contains 2C:1A:00:00:00:00:00:00 port=0, which appears to be derived from
 * Mellanox switch or some other intermediate device, not our NIC MAC.
 * We hardcode this value to match what DTN sends back.
 */
void ptp_init_port_identity(ptp_session_t *session, uint16_t port_id)
{
    (void)port_id;  // Not used - DTN uses different identification

    // DTN returns requesting_port_id as: 2C:1A:00:00:00:00:00:00 port=0
    // This appears to be from Mellanox switch, not our NIC MAC
    session->our_port_id.clock_identity[0] = 0x2C;
    session->our_port_id.clock_identity[1] = 0x1A;
    session->our_port_id.clock_identity[2] = 0x00;
    session->our_port_id.clock_identity[3] = 0x00;
    session->our_port_id.clock_identity[4] = 0x00;
    session->our_port_id.clock_identity[5] = 0x00;
    session->our_port_id.clock_identity[6] = 0x00;
    session->our_port_id.clock_identity[7] = 0x00;

    // DTN uses port number 0
    session->our_port_id.port_number = rte_cpu_to_be_16(0);
}
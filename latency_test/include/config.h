/**
 * @file config.h
 * @brief HW Timestamp Latency Test - Configuration
 *
 * This file contains all port, VLAN, VL-ID and timing configurations.
 * Standalone application - does not require DPDK.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

// ============================================
// TIMING CONFIGURATION
// ============================================
#define DEFAULT_PACKET_INTERVAL_US  32      // Delay between VLAN tests (µs)
#define DEFAULT_PACKET_COUNT        1       // Default packet count per VLAN
#define DEFAULT_PACKET_SIZE         1518    // Default packet size (bytes)
#define DEFAULT_TIMEOUT_MS          1       // RX timeout (milliseconds) - 1 ms
#define DEFAULT_MAX_LATENCY_NS      30000   // Maximum acceptable latency (nanoseconds) - 30 µs
#define DEFAULT_RETRY_COUNT         3       // Retry count on failure
#define MIN_PACKET_SIZE             64      // Minimum Ethernet frame
#define MAX_PACKET_SIZE             1518    // Maximum Ethernet frame (no jumbo)

// ============================================
// PORT CONFIGURATION
// ============================================
#define NUM_PORT_PAIRS      8
#define MAX_VLANS_PER_PAIR  4

/**
 * Port pair structure
 * Packet sent from TX port, received on RX port
 */
struct port_pair {
    uint16_t    tx_port;                    // TX port ID (0-7)
    const char *tx_iface;                   // TX interface name (e.g., "ens1f0np0")
    uint16_t    rx_port;                    // RX port ID (0-7)
    const char *rx_iface;                   // RX interface name
    uint16_t    vlans[MAX_VLANS_PER_PAIR];  // VLAN IDs
    uint16_t    vl_ids[MAX_VLANS_PER_PAIR]; // VL-IDs (last 2 bytes of MAC/IP)
    uint16_t    vlan_count;                 // VLAN count for this pair
};

/**
 * Port pairs definition
 *
 * Connection diagram:
 *   Port 0 (ens2f0np0) <-> Port 7 (ens5f1np1)
 *   Port 1 (ens2f1np1) <-> Port 6 (ens5f0np0)
 *   Port 2 (ens1f0np0) <-> Port 5 (ens3f1np1)
 *   Port 3 (ens1f1np1) <-> Port 4 (ens3f0np0)
 */
static const struct port_pair g_port_pairs[NUM_PORT_PAIRS] = {
    // TX Port | TX Interface  | RX Port | RX Interface  | VLANs              | VL-IDs                    | Count
    {0, "ens2f0np0", 7, "ens5f1np1", {105, 106, 107, 108}, {1027, 1155, 1283, 1411}, 4},
    {1, "ens2f1np1", 6, "ens5f0np0", {109, 110, 111, 112}, {1539, 1667, 1795, 1923}, 4},
    {2, "ens1f0np0", 5, "ens3f1np1", {97,  98,  99,  100}, {3,    131,  259,  387 }, 4},
    {3, "ens1f1np1", 4, "ens3f0np0", {101, 102, 103, 104}, {515,  643,  771,  899 }, 4},
    {4, "ens3f0np0", 3, "ens1f1np1", {113, 114, 115, 116}, {2051, 2179, 2307, 2435}, 4},
    {5, "ens3f1np1", 2, "ens1f0np0", {117, 118, 119, 120}, {2563, 2691, 2819, 2947}, 4},
    {6, "ens5f0np0", 1, "ens2f1np1", {121, 122, 123, 124}, {3075, 3203, 3331, 3459}, 4},
    {7, "ens5f1np1", 0, "ens2f0np0", {125, 126, 127, 128}, {3587, 3715, 3843, 3971}, 4},
};

// ============================================
// PACKET FORMAT CONFIGURATION
// ============================================

// Ethernet
#define ETH_ALEN            6
#define ETH_P_8021Q         0x8100      // VLAN tagged frame
#define ETH_P_IP            0x0800      // IPv4

// Source MAC: 02:00:00:00:00:20
static const uint8_t g_src_mac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x20};

// Destination MAC prefix: 03:00:00:00:XX:XX (XX:XX = VL-ID)
static const uint8_t g_dst_mac_prefix[4] = {0x03, 0x00, 0x00, 0x00};

// IP Configuration
#define PKT_IP_VERSION      4
#define PKT_IP_IHL          5           // 20 bytes header
#define PKT_IP_TOS          0
#define PKT_IP_TTL          1
#define PKT_IP_PROTOCOL_UDP 17

// Source IP: 10.0.0.0
#define SRC_IP_ADDR         0x0A000000

// Destination IP prefix: 224.224.XX.XX (XX.XX = VL-ID)
#define DST_IP_PREFIX       0xE0E00000

// UDP Configuration
#define UDP_SRC_PORT        100
#define UDP_DST_PORT        100

// ============================================
// PAYLOAD CONFIGURATION
// ============================================
// Payload format: [8 bytes sequence] [data...]
#define SEQ_NUM_SIZE        8           // Sequence number size (bytes)

// ============================================
// HEADER SIZES
// ============================================
#define ETH_HDR_SIZE        14          // Ethernet header
#define VLAN_HDR_SIZE       4           // 802.1Q VLAN tag
#define IP_HDR_SIZE         20          // IPv4 header (no options)
#define UDP_HDR_SIZE        8           // UDP header
#define TOTAL_HDR_SIZE      (ETH_HDR_SIZE + VLAN_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE)  // 46 bytes
#define TOTAL_HDR_SIZE_UNTAGGED (ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE)  // 42 bytes (no VLAN)

// ============================================
// DEBUG LEVELS
// ============================================
#define DEBUG_LEVEL_NONE    0           // Results table only
#define DEBUG_LEVEL_INFO    1           // Basic information
#define DEBUG_LEVEL_VERBOSE 2           // Detailed information
#define DEBUG_LEVEL_TRACE   3           // Everything (including packet hex dump)

#endif // CONFIG_H

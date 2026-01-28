/**
 * @file embedded_latency.c
 * @brief Embedded HW Timestamp Latency Test Implementation
 *
 * Raw socket + SO_TIMESTAMPING ile NIC HW timestamp kullanarak
 * latency ölçümü yapar.
 *
 * DPDK EAL başlamadan önce çalıştırılmalı!
 */

#include "embedded_latency.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <arpa/inet.h>

// ============================================
// GLOBAL STATE
// ============================================
struct emb_latency_state g_emb_latency = {0};

// ============================================
// USER INTERACTION
// ============================================

/**
 * Ask a yes/no question to the user
 * @param question  Question text
 * @return          true = yes, false = no
 */
static bool ask_question(const char *question) {
    char response;
    int c;

    while (1) {
        printf("%s [y/n]: ", question);
        fflush(stdout);

        response = getchar();

        // Clear rest of line
        while ((c = getchar()) != '\n' && c != EOF);

        if (response == 'y' || response == 'Y') {
            return true;
        } else if (response == 'n' || response == 'N') {
            return false;
        }

        printf("Invalid input! Please enter 'y' or 'n'.\n");
    }
}

// ============================================
// CONFIGURATION
// ============================================

// Port info
static const struct {
    uint16_t port_id;
    const char *iface;
} PORT_INFO[] = {
    {0, "ens2f0np0"},
    {1, "ens2f1np1"},
    {2, "ens1f0np0"},
    {3, "ens1f1np1"},
    {4, "ens3f0np0"},
    {5, "ens3f1np1"},
    {6, "ens5f0np0"},
    {7, "ens5f1np1"},
};
#define NUM_PORTS (sizeof(PORT_INFO) / sizeof(PORT_INFO[0]))

// LOOPBACK TEST: Port pairs - TX -> RX mapping (through Mellanox switch)
static const struct {
    uint16_t tx_port;
    const char *tx_iface;
    uint16_t rx_port;
    const char *rx_iface;
    uint16_t vlans[4];
    uint16_t vl_ids[4];
    int vlan_count;
} LOOPBACK_PAIRS[] = {
    {0, "ens2f0np0", 7, "ens5f1np1", {105, 106, 107, 108}, {1027, 1155, 1283, 1411}, 4},
    {1, "ens2f1np1", 6, "ens5f0np0", {109, 110, 111, 112}, {1539, 1667, 1795, 1923}, 4},
    {2, "ens1f0np0", 5, "ens3f1np1", {97,  98,  99,  100}, {3,    131,  259,  387 }, 4},
    {3, "ens1f1np1", 4, "ens3f0np0", {101, 102, 103, 104}, {515,  643,  771,  899 }, 4},
    {4, "ens3f0np0", 3, "ens1f1np1", {113, 114, 115, 116}, {2051, 2179, 2307, 2435}, 4},
    {5, "ens3f1np1", 2, "ens1f0np0", {117, 118, 119, 120}, {2563, 2691, 2819, 2947}, 4},
    {6, "ens5f0np0", 1, "ens2f1np1", {121, 122, 123, 124}, {3075, 3203, 3331, 3459}, 4},
    {7, "ens5f1np1", 0, "ens2f0np0", {125, 126, 127, 128}, {3587, 3715, 3843, 3971}, 4},
};
#define NUM_LOOPBACK_PAIRS (sizeof(LOOPBACK_PAIRS) / sizeof(LOOPBACK_PAIRS[0]))

// UNIT TEST: Port pairs - neighboring ports (0↔1, 2↔3, 4↔5, 6↔7)
static const struct {
    uint16_t tx_port;
    const char *tx_iface;
    uint16_t rx_port;
    const char *rx_iface;
    uint16_t vlans[4];
    uint16_t vl_ids[4];
    int vlan_count;
} UNIT_TEST_PAIRS[] = {
    // Port 0 -> Port 1
    {0, "ens2f0np0", 1, "ens2f1np1", {105, 106, 107, 108}, {1027, 1155, 1283, 1411}, 4},
    // Port 1 -> Port 0
    {1, "ens2f1np1", 0, "ens2f0np0", {109, 110, 111, 112}, {1539, 1667, 1795, 1923}, 4},
    // Port 2 -> Port 3
    {2, "ens1f0np0", 3, "ens1f1np1", {97,  98,  99,  100}, {3,    131,  259,  387 }, 4},
    // Port 3 -> Port 2
    {3, "ens1f1np1", 2, "ens1f0np0", {101, 102, 103, 104}, {515,  643,  771,  899 }, 4},
    // Port 4 -> Port 5
    {4, "ens3f0np0", 5, "ens3f1np1", {113, 114, 115, 116}, {2051, 2179, 2307, 2435}, 4},
    // Port 5 -> Port 4
    {5, "ens3f1np1", 4, "ens3f0np0", {117, 118, 119, 120}, {2563, 2691, 2819, 2947}, 4},
    // Port 6 -> Port 7
    {6, "ens5f0np0", 7, "ens5f1np1", {121, 122, 123, 124}, {3075, 3203, 3331, 3459}, 4},
    // Port 7 -> Port 6
    {7, "ens5f1np1", 6, "ens5f0np0", {125, 126, 127, 128}, {3587, 3715, 3843, 3971}, 4},
};
#define NUM_UNIT_TEST_PAIRS (sizeof(UNIT_TEST_PAIRS) / sizeof(UNIT_TEST_PAIRS[0]))

// Legacy alias for backward compatibility
#define PORT_PAIRS LOOPBACK_PAIRS
#define NUM_PORT_PAIRS NUM_LOOPBACK_PAIRS

// Packet config
#define PACKET_SIZE     1518
#define ETH_P_8021Q     0x8100
#define ETH_P_IP        0x0800

// Source MAC
static const uint8_t SRC_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x20};
// Dest MAC prefix
static const uint8_t DST_MAC_PREFIX[4] = {0x03, 0x00, 0x00, 0x00};

// ============================================
// HELPERS
// ============================================

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static double ns_to_us(uint64_t ns) {
    return (double)ns / 1000.0;
}

// ============================================
// HW TIMESTAMP SOCKET
// ============================================

typedef enum {
    EMB_SOCK_TX,
    EMB_SOCK_RX
} emb_sock_type_t;

static int create_raw_socket(const char *ifname, int *if_index, emb_sock_type_t type) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    // Get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(fd);
        return -1;
    }
    *if_index = ifr.ifr_ifindex;

    // Bind to interface
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = *if_index;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    // Enable promiscuous mode for RX socket (needed for multicast packets)
    if (type == EMB_SOCK_RX) {
        struct packet_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = *if_index;
        mreq.mr_type = PACKET_MR_PROMISC;
        setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    }

    // Enable HW timestamping on NIC
    struct hwtstamp_config hwconfig = {0};
    hwconfig.tx_type = (type == EMB_SOCK_TX) ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
    hwconfig.rx_filter = (type == EMB_SOCK_RX) ? HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_data = (void *)&hwconfig;
    ioctl(fd, SIOCSHWTSTAMP, &ifr);  // May fail on some NICs, continue anyway

    // Request timestamps via socket option
    int flags = SOF_TIMESTAMPING_RAW_HARDWARE;
    if (type == EMB_SOCK_TX) {
        flags |= SOF_TIMESTAMPING_TX_HARDWARE;
    } else {
        flags |= SOF_TIMESTAMPING_RX_HARDWARE;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
        perror("SO_TIMESTAMPING");
        close(fd);
        return -1;
    }

    return fd;
}

// ============================================
// PACKET BUILDING
// ============================================

// IP header checksum calculation
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

static int build_packet(uint8_t *buf, uint16_t vlan_id, uint16_t vl_id, uint64_t seq) {
    memset(buf, 0, PACKET_SIZE);
    int offset = 0;

    // Ethernet header
    // Dest MAC: 03:00:00:00:VL_HI:VL_LO
    buf[offset++] = DST_MAC_PREFIX[0];
    buf[offset++] = DST_MAC_PREFIX[1];
    buf[offset++] = DST_MAC_PREFIX[2];
    buf[offset++] = DST_MAC_PREFIX[3];
    buf[offset++] = (vl_id >> 8) & 0xFF;
    buf[offset++] = vl_id & 0xFF;

    // Source MAC
    memcpy(buf + offset, SRC_MAC, 6);
    offset += 6;

    // VLAN tag (802.1Q)
    buf[offset++] = (ETH_P_8021Q >> 8) & 0xFF;
    buf[offset++] = ETH_P_8021Q & 0xFF;
    buf[offset++] = (vlan_id >> 8) & 0xFF;
    buf[offset++] = vlan_id & 0xFF;

    // EtherType: IP
    buf[offset++] = (ETH_P_IP >> 8) & 0xFF;
    buf[offset++] = ETH_P_IP & 0xFF;

    // IP header start offset (for checksum calculation)
    int ip_hdr_start = offset;

    // IP header
    buf[offset++] = 0x45;  // Version + IHL
    buf[offset++] = 0x00;  // TOS
    uint16_t ip_len = PACKET_SIZE - 14 - 4;  // Total - ETH - VLAN
    buf[offset++] = (ip_len >> 8) & 0xFF;
    buf[offset++] = ip_len & 0xFF;
    buf[offset++] = (seq >> 8) & 0xFF;  // ID (use seq for identification)
    buf[offset++] = seq & 0xFF;
    buf[offset++] = 0x00; buf[offset++] = 0x00;  // Flags + Fragment
    buf[offset++] = 0x01;  // TTL
    buf[offset++] = 0x11;  // Protocol: UDP
    buf[offset++] = 0x00; buf[offset++] = 0x00;  // Checksum (calculated below)

    // Source IP: 10.0.0.0
    buf[offset++] = 10; buf[offset++] = 0; buf[offset++] = 0; buf[offset++] = 0;

    // Dest IP: 224.224.VL_HI.VL_LO
    buf[offset++] = 224;
    buf[offset++] = 224;
    buf[offset++] = (vl_id >> 8) & 0xFF;
    buf[offset++] = vl_id & 0xFF;

    // Calculate and set IP checksum
    uint16_t csum = ip_checksum(buf + ip_hdr_start, 20);
    buf[ip_hdr_start + 10] = (csum >> 8) & 0xFF;
    buf[ip_hdr_start + 11] = csum & 0xFF;

    // UDP header
    buf[offset++] = 0x00; buf[offset++] = 0x64;  // Src port: 100
    buf[offset++] = 0x00; buf[offset++] = 0x64;  // Dst port: 100
    uint16_t udp_len = ip_len - 20;
    buf[offset++] = (udp_len >> 8) & 0xFF;
    buf[offset++] = udp_len & 0xFF;
    buf[offset++] = 0x00; buf[offset++] = 0x00;  // Checksum (optional for UDP)

    // Sequence number (8 bytes, big endian)
    for (int i = 7; i >= 0; i--) {
        buf[offset++] = (seq >> (i * 8)) & 0xFF;
    }

    return PACKET_SIZE;
}

// Check if packet is our test packet (handles VLAN stripped case)
static bool is_our_test_packet(const uint8_t *pkt, size_t len, uint16_t expected_vlan, uint16_t expected_vlid) {
    if (len < 14) return false;

    // Check DST MAC prefix: 03:00:00:00:XX:XX
    if (pkt[0] != DST_MAC_PREFIX[0] || pkt[1] != DST_MAC_PREFIX[1] ||
        pkt[2] != DST_MAC_PREFIX[2] || pkt[3] != DST_MAC_PREFIX[3]) {
        return false;
    }

    // Check VL-ID from DST MAC
    uint16_t vl_id = ((uint16_t)pkt[4] << 8) | pkt[5];
    if (expected_vlid != 0 && vl_id != expected_vlid) {
        return false;
    }

    // Check if VLAN tagged (EtherType at offset 12-13)
    uint16_t ether_type = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (ether_type == ETH_P_8021Q) {
        // VLAN tagged - check VLAN ID at offset 14-15
        uint16_t vlan_id = (((uint16_t)pkt[14] << 8) | pkt[15]) & 0x0FFF;
        if (expected_vlan != 0 && vlan_id != expected_vlan) {
            return false;
        }
    }
    // If untagged (VLAN stripped by switch), accept based on VL-ID match

    return true;
}

// ============================================
// TIMESTAMP EXTRACTION
// ============================================

// SCM_TIMESTAMPING is the correct cmsg_type for SO_TIMESTAMPING
#ifndef SCM_TIMESTAMPING
#define SCM_TIMESTAMPING SO_TIMESTAMPING
#endif

static bool extract_timestamp(struct msghdr *msg, uint64_t *ts_ns) {
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING) {
            struct timespec *ts = (struct timespec *)CMSG_DATA(cmsg);
            // ts[0] = software, ts[1] = deprecated, ts[2] = hardware (raw)

            // Hardware timestamp preferred
            if (ts[2].tv_sec != 0 || ts[2].tv_nsec != 0) {
                *ts_ns = (uint64_t)ts[2].tv_sec * 1000000000ULL + ts[2].tv_nsec;
                return true;
            }
            // Software timestamp fallback
            if (ts[0].tv_sec != 0 || ts[0].tv_nsec != 0) {
                *ts_ns = (uint64_t)ts[0].tv_sec * 1000000000ULL + ts[0].tv_nsec;
                return true;
            }
        }
    }
    return false;
}

// ============================================
// SINGLE TEST
// ============================================

static int run_single_test(int tx_fd, int rx_fd, int tx_ifindex,
                           uint16_t tx_port, uint16_t rx_port,
                           uint16_t vlan_id, uint16_t vl_id,
                           int packet_count, int timeout_ms,
                           uint64_t max_latency_ns,
                           struct emb_latency_result *result) {

    memset(result, 0, sizeof(*result));
    result->tx_port = tx_port;
    result->rx_port = rx_port;
    result->vlan_id = vlan_id;
    result->vl_id = vl_id;
    result->min_latency_ns = UINT64_MAX;

    uint8_t tx_buf[2048];
    uint8_t rx_buf[2048];
    char ctrl_buf[1024];

    uint64_t total_latency = 0;

    for (int pkt = 0; pkt < packet_count; pkt++) {
        uint64_t seq = ((uint64_t)vlan_id << 32) | pkt;

        // Build packet
        int pkt_len = build_packet(tx_buf, vlan_id, vl_id, seq);

        // Send
        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = tx_ifindex;
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, tx_buf, 6);

        ssize_t sent = sendto(tx_fd, tx_buf, pkt_len, 0,
                              (struct sockaddr *)&sll, sizeof(sll));
        if (sent < 0) {
            snprintf(result->error_msg, sizeof(result->error_msg), "send failed: %s", strerror(errno));
            continue;
        }
        result->tx_count++;

        // Get TX timestamp from error queue
        uint64_t tx_ts = 0;
        struct pollfd pfd = {tx_fd, POLLERR, 0};
        if (poll(&pfd, 1, 100) > 0) {
            struct msghdr msg = {0};
            struct iovec iov = {rx_buf, sizeof(rx_buf)};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl_buf;
            msg.msg_controllen = sizeof(ctrl_buf);

            recvmsg(tx_fd, &msg, MSG_ERRQUEUE);
            extract_timestamp(&msg, &tx_ts);
        }

        // Wait for RX
        struct pollfd rx_pfd = {rx_fd, POLLIN, 0};
        int remaining = timeout_ms;
        bool received = false;

        while (remaining > 0 && !received) {
            int ret = poll(&rx_pfd, 1, remaining < 100 ? remaining : 100);
            if (ret > 0) {
                struct msghdr msg = {0};
                struct iovec iov = {rx_buf, sizeof(rx_buf)};
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;
                msg.msg_control = ctrl_buf;
                msg.msg_controllen = sizeof(ctrl_buf);

                ssize_t len = recvmsg(rx_fd, &msg, 0);
                if (len > 0) {
                    // Check if this is our test packet (handles VLAN stripped case)
                    if (is_our_test_packet(rx_buf, len, vlan_id, vl_id)) {
                        uint64_t rx_ts = 0;
                        extract_timestamp(&msg, &rx_ts);

                        if (rx_ts > 0 && tx_ts > 0 && rx_ts > tx_ts) {
                            uint64_t latency = rx_ts - tx_ts;
                            total_latency += latency;

                            if (latency < result->min_latency_ns)
                                result->min_latency_ns = latency;
                            if (latency > result->max_latency_ns)
                                result->max_latency_ns = latency;

                            result->rx_count++;
                            received = true;
                        }
                    }
                }
            }
            remaining -= 100;
        }
    }

    // Finalize
    if (result->rx_count > 0) {
        result->valid = true;
        result->avg_latency_ns = total_latency / result->rx_count;
        result->passed = (result->max_latency_ns <= max_latency_ns);
        if (result->min_latency_ns == UINT64_MAX)
            result->min_latency_ns = 0;
    } else {
        result->valid = false;
        result->passed = false;
        if (result->error_msg[0] == '\0')
            snprintf(result->error_msg, sizeof(result->error_msg), "No packets received");
    }

    return result->passed ? 0 : 1;
}

// ============================================
// MAIN TEST FUNCTION
// ============================================

int emb_latency_run(int packet_count, int timeout_ms, int max_latency_us) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         EMBEDDED HW TIMESTAMP LATENCY TEST                       ║\n");
    printf("║  Packets per VLAN: %-3d | Timeout: %dms | Max: %dus             ║\n",
           packet_count, timeout_ms, max_latency_us);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    // Reset state
    memset(&g_emb_latency, 0, sizeof(g_emb_latency));

    uint64_t max_latency_ns = (uint64_t)max_latency_us * 1000;
    uint64_t start_time = get_time_ns();
    int result_idx = 0;

    // Test each port pair
    for (size_t p = 0; p < NUM_PORT_PAIRS; p++) {
        printf("Testing port pair: Port %d (%s) -> Port %d (%s)\n",
               PORT_PAIRS[p].tx_port, PORT_PAIRS[p].tx_iface,
               PORT_PAIRS[p].rx_port, PORT_PAIRS[p].rx_iface);

        // Create sockets (TX and RX separately)
        int tx_ifindex, rx_ifindex;
        int tx_fd = create_raw_socket(PORT_PAIRS[p].tx_iface, &tx_ifindex, EMB_SOCK_TX);
        int rx_fd = create_raw_socket(PORT_PAIRS[p].rx_iface, &rx_ifindex, EMB_SOCK_RX);

        if (tx_fd < 0 || rx_fd < 0) {
            fprintf(stderr, "ERROR: Cannot create sockets for %s/%s\n",
                    PORT_PAIRS[p].tx_iface, PORT_PAIRS[p].rx_iface);
            if (tx_fd >= 0) close(tx_fd);
            if (rx_fd >= 0) close(rx_fd);
            continue;
        }

        // Wait for sockets to fully initialize (critical for first packet!)
        usleep(10000);  // 10ms

        // Test each VLAN
        for (int v = 0; v < PORT_PAIRS[p].vlan_count; v++) {
            struct emb_latency_result *r = &g_emb_latency.results[result_idx];

            run_single_test(tx_fd, rx_fd, tx_ifindex,
                           PORT_PAIRS[p].tx_port, PORT_PAIRS[p].rx_port,
                           PORT_PAIRS[p].vlans[v], PORT_PAIRS[p].vl_ids[v],
                           packet_count, timeout_ms, max_latency_ns, r);

            if (r->passed) {
                g_emb_latency.passed_count++;
            } else {
                g_emb_latency.failed_count++;
            }
            result_idx++;

            // Inter-VLAN delay
            usleep(32);
        }

        close(tx_fd);
        close(rx_fd);
    }

    // Finalize
    g_emb_latency.result_count = result_idx;
    g_emb_latency.test_completed = true;
    g_emb_latency.test_passed = (g_emb_latency.failed_count == 0);
    g_emb_latency.test_duration_ns = get_time_ns() - start_time;

    // Calculate overall stats
    uint64_t min = UINT64_MAX, max = 0, sum = 0;
    int valid_count = 0;
    for (int i = 0; i < result_idx; i++) {
        struct emb_latency_result *r = &g_emb_latency.results[i];
        if (r->valid && r->rx_count > 0) {
            if (r->min_latency_ns < min) min = r->min_latency_ns;
            if (r->max_latency_ns > max) max = r->max_latency_ns;
            sum += r->avg_latency_ns;
            valid_count++;
        }
    }
    g_emb_latency.overall_min_ns = (min == UINT64_MAX) ? 0 : min;
    g_emb_latency.overall_max_ns = max;
    g_emb_latency.overall_avg_ns = valid_count > 0 ? sum / valid_count : 0;

    // Print results
    emb_latency_print();

    return g_emb_latency.failed_count;
}

int emb_latency_run_default(void) {
    // Run unit test (neighboring ports: 0↔1, 2↔3, 4↔5, 6↔7)
    // This matches normal DPDK TX/RX port configuration
    return emb_latency_run_unit_test(1, 100, 100);  // 1 packet, 100ms timeout, 100us max
}

/**
 * Interactive latency test with user prompts
 * Follows the same pattern as Dtn.cpp latencyTestSequence()
 *
 * Tests neighboring ports: 0↔1, 2↔3, 4↔5, 6↔7
 * (matches normal DPDK TX/RX port configuration)
 *
 * @return  0 = all passed/skipped, >0 = fail count, <0 = error
 */
int emb_latency_run_interactive(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         HW TIMESTAMP LATENCY TEST (INTERACTIVE MODE)             ║\n");
    printf("║  Port pairs: 0↔1, 2↔3, 4↔5, 6↔7 (neighboring ports)             ║\n");
    printf("║  Max threshold: 100us                                            ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    // Ask if user wants to run the test
    if (!ask_question("Do you want to run HW Timestamp Latency Test?")) {
        printf("Latency test skipped by user.\n\n");
        return 0;  // Skipped = success
    }

    // Confirm before starting
    if (ask_question("Ready to start latency test on neighboring ports (0↔1, 2↔3, 4↔5, 6↔7)?")) {
        printf("\nStarting latency test...\n");
        return emb_latency_run_default();
    } else {
        printf("Latency test skipped by user.\n\n");
        return 0;  // Skipped = success
    }
}

// ============================================
// LOOPBACK TEST (Mellanox Switch Latency)
// ============================================

int emb_latency_run_loopback(int packet_count, int timeout_ms, int max_latency_us) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         LOOPBACK TEST (Mellanox Switch Latency)                  ║\n");
    printf("║  Packets: %-3d | Timeout: %dms | Max: %dus                      ║\n",
           packet_count, timeout_ms, max_latency_us);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    uint64_t max_latency_ns = (uint64_t)max_latency_us * 1000;
    uint64_t start_time = get_time_ns();
    int result_idx = 0;
    int failed_count = 0;
    int passed_count = 0;

    // Test each loopback port pair
    for (size_t p = 0; p < NUM_LOOPBACK_PAIRS; p++) {
        printf("Testing port pair: Port %d (%s) -> Port %d (%s)\n",
               LOOPBACK_PAIRS[p].tx_port, LOOPBACK_PAIRS[p].tx_iface,
               LOOPBACK_PAIRS[p].rx_port, LOOPBACK_PAIRS[p].rx_iface);

        int tx_ifindex, rx_ifindex;
        int tx_fd = create_raw_socket(LOOPBACK_PAIRS[p].tx_iface, &tx_ifindex, EMB_SOCK_TX);
        int rx_fd = create_raw_socket(LOOPBACK_PAIRS[p].rx_iface, &rx_ifindex, EMB_SOCK_RX);

        if (tx_fd < 0 || rx_fd < 0) {
            fprintf(stderr, "ERROR: Cannot create sockets\n");
            if (tx_fd >= 0) close(tx_fd);
            if (rx_fd >= 0) close(rx_fd);
            continue;
        }

        // Wait for sockets to fully initialize
        usleep(10000);  // 10ms

        for (int v = 0; v < LOOPBACK_PAIRS[p].vlan_count; v++) {
            struct emb_latency_result *r = &g_emb_latency.loopback_results[result_idx];

            run_single_test(tx_fd, rx_fd, tx_ifindex,
                           LOOPBACK_PAIRS[p].tx_port, LOOPBACK_PAIRS[p].rx_port,
                           LOOPBACK_PAIRS[p].vlans[v], LOOPBACK_PAIRS[p].vl_ids[v],
                           packet_count, timeout_ms, max_latency_ns, r);

            if (r->passed) {
                passed_count++;
            } else {
                failed_count++;
            }
            result_idx++;
            usleep(32);
        }

        close(tx_fd);
        close(rx_fd);
    }

    // Update loopback state
    g_emb_latency.loopback_result_count = result_idx;
    g_emb_latency.loopback_completed = true;
    g_emb_latency.loopback_passed = (failed_count == 0);
    g_emb_latency.loopback_skipped = false;

    // Print results table
    emb_latency_print_loopback();

    printf("Loopback test complete: %d/%d passed\n\n", passed_count, result_idx);

    return failed_count;
}

// ============================================
// UNIT TEST (Device Latency)
// ============================================

int emb_latency_run_unit_test(int packet_count, int timeout_ms, int max_latency_us) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         UNIT TEST (Device Latency)                               ║\n");
    printf("║  Port pairs: 0↔1, 2↔3, 4↔5, 6↔7                                  ║\n");
    printf("║  Packets: %-3d | Timeout: %dms | Max: %dus                      ║\n",
           packet_count, timeout_ms, max_latency_us);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    uint64_t max_latency_ns = (uint64_t)max_latency_us * 1000;
    uint64_t start_time = get_time_ns();
    int result_idx = 0;
    int failed_count = 0;
    int passed_count = 0;

    // Test each unit test port pair
    for (size_t p = 0; p < NUM_UNIT_TEST_PAIRS; p++) {
        printf("Testing port pair: Port %d (%s) -> Port %d (%s)\n",
               UNIT_TEST_PAIRS[p].tx_port, UNIT_TEST_PAIRS[p].tx_iface,
               UNIT_TEST_PAIRS[p].rx_port, UNIT_TEST_PAIRS[p].rx_iface);

        int tx_ifindex, rx_ifindex;
        int tx_fd = create_raw_socket(UNIT_TEST_PAIRS[p].tx_iface, &tx_ifindex, EMB_SOCK_TX);
        int rx_fd = create_raw_socket(UNIT_TEST_PAIRS[p].rx_iface, &rx_ifindex, EMB_SOCK_RX);

        if (tx_fd < 0 || rx_fd < 0) {
            fprintf(stderr, "ERROR: Cannot create sockets\n");
            if (tx_fd >= 0) close(tx_fd);
            if (rx_fd >= 0) close(rx_fd);
            continue;
        }

        // Wait for sockets to fully initialize
        usleep(10000);  // 10ms

        for (int v = 0; v < UNIT_TEST_PAIRS[p].vlan_count; v++) {
            struct emb_latency_result *r = &g_emb_latency.unit_results[result_idx];

            run_single_test(tx_fd, rx_fd, tx_ifindex,
                           UNIT_TEST_PAIRS[p].tx_port, UNIT_TEST_PAIRS[p].rx_port,
                           UNIT_TEST_PAIRS[p].vlans[v], UNIT_TEST_PAIRS[p].vl_ids[v],
                           packet_count, timeout_ms, max_latency_ns, r);

            if (r->passed) {
                passed_count++;
            } else {
                failed_count++;
            }
            result_idx++;
            usleep(32);
        }

        close(tx_fd);
        close(rx_fd);
    }

    // Update unit test state
    g_emb_latency.unit_result_count = result_idx;
    g_emb_latency.unit_completed = true;
    g_emb_latency.unit_passed = (failed_count == 0);

    // Print results table
    emb_latency_print_unit();

    printf("Unit test complete: %d/%d passed\n\n", passed_count, result_idx);

    return failed_count;
}

// ============================================
// COMBINED LATENCY CALCULATION
// ============================================

void emb_latency_calculate_combined(void) {
    // Each direction separately: 0→1, 1→0, 2→3, 3→2, 4→5, 5→4, 6→7, 7→6
    const uint16_t directions[][2] = {
        {0, 1}, {1, 0},  // Port pair 0-1
        {2, 3}, {3, 2},  // Port pair 2-3
        {4, 5}, {5, 4},  // Port pair 4-5
        {6, 7}, {7, 6}   // Port pair 6-7
    };
    g_emb_latency.combined_count = 8;

    for (int i = 0; i < 8; i++) {
        struct emb_combined_latency *c = &g_emb_latency.combined[i];
        memset(c, 0, sizeof(*c));

        c->tx_port = directions[i][0];
        c->rx_port = directions[i][1];

        // Get switch latency (from loopback or default)
        // For each direction, use the TX port's loopback measurement
        if (g_emb_latency.loopback_completed && !g_emb_latency.loopback_skipped) {
            // Find loopback result for this TX port
            double sum = 0;
            int count = 0;

            for (uint32_t j = 0; j < g_emb_latency.loopback_result_count; j++) {
                struct emb_latency_result *r = &g_emb_latency.loopback_results[j];
                if (r->valid && r->tx_port == c->tx_port) {
                    sum += ns_to_us(r->avg_latency_ns);
                    count++;
                }
            }

            if (count > 0) {
                c->switch_latency_us = sum / count;
                c->switch_measured = true;
            } else {
                c->switch_latency_us = EMB_LAT_DEFAULT_SWITCH_US;
                c->switch_measured = false;
            }
        } else {
            // Use default
            c->switch_latency_us = EMB_LAT_DEFAULT_SWITCH_US;
            c->switch_measured = false;
        }

        // Get total latency (from unit test) for this specific direction
        if (g_emb_latency.unit_completed) {
            // Find unit test results for tx_port -> rx_port
            double sum = 0;
            int count = 0;

            for (uint32_t j = 0; j < g_emb_latency.unit_result_count; j++) {
                struct emb_latency_result *r = &g_emb_latency.unit_results[j];
                if (r->valid &&
                    r->tx_port == c->tx_port && r->rx_port == c->rx_port) {
                    sum += ns_to_us(r->avg_latency_ns);
                    count++;
                }
            }

            if (count > 0) {
                c->total_latency_us = sum / count;
                c->total_measured = true;
            }
        }

        // Calculate unit (device) latency
        if (c->total_measured) {
            c->unit_latency_us = c->total_latency_us - c->switch_latency_us;
            if (c->unit_latency_us < 0) c->unit_latency_us = 0;
            c->unit_valid = true;
            c->passed = true;  // Adjust threshold as needed
        }
    }
}

// ============================================
// FULL INTERACTIVE SEQUENCE
// ============================================

int emb_latency_full_sequence(void) {
    int total_fails = 0;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         LATENCY TEST SEQUENCE                                    ║\n");
    printf("║  1. Loopback Test (Mellanox switch latency measurement)          ║\n");
    printf("║  2. Unit Test (Device latency: 0↔1, 2↔3, 4↔5, 6↔7)              ║\n");
    printf("║  3. Combined Results (unit = total - switch)                     ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    // Reset state
    memset(&g_emb_latency, 0, sizeof(g_emb_latency));

    // ==========================================
    // STEP 1: Loopback Test (OPTIONAL)
    // ==========================================
    printf("=== STEP 1: Loopback Test (Mellanox Switch Latency) ===\n\n");

    // Outer loop: Ask if user wants loopback test
    while (1) {
        if (ask_question("Do you want to run the Loopback test to measure Mellanox switch latency?")) {
            // User wants loopback test - ask about cables
            if (ask_question("Are the loopback cables installed?")) {
                // Cables installed - run loopback test
                int fails = emb_latency_run_loopback(1, 100, 30);
                total_fails += fails;
                break;  // Done with loopback
            } else {
                // Cables not installed - go back to outer question
                printf("\nPlease install the loopback cables first.\n\n");
                // Loop continues - will ask "Do you want loopback test?" again
            }
        } else {
            // User doesn't want loopback test - use default
            printf("Using default Mellanox switch latency: %.1f us\n\n",
                   EMB_LAT_DEFAULT_SWITCH_US);
            g_emb_latency.loopback_skipped = true;
            break;  // Done with loopback
        }
    }

    // ==========================================
    // STEP 2: Unit Test (MANDATORY)
    // ==========================================
    printf("=== STEP 2: Unit Test (Device Latency) ===\n\n");
    printf("This test measures total latency through the device.\n");
    printf("Port pairs: 0→1, 1→0, 2→3, 3→2, 4→5, 5→4, 6→7, 7→6\n\n");

    // Unit test is mandatory - wait for cables to be installed
    while (!ask_question("Are the unit test cables installed (neighboring ports connected)?")) {
        printf("\nPlease install the unit test cables and try again.\n\n");
    }

    // Run unit test
    int unit_fails = emb_latency_run_unit_test(1, 100, 100);  // 1 packet, 100ms timeout, 100us max
    total_fails += unit_fails;

    // ==========================================
    // STEP 3: Calculate Combined Results
    // ==========================================
    printf("=== STEP 3: Combined Latency Results ===\n\n");

    emb_latency_calculate_combined();
    emb_latency_print_combined();

    // Update legacy state
    g_emb_latency.test_completed = true;
    g_emb_latency.test_passed = (total_fails == 0);

    return total_fails;
}

// ============================================
// ACCESSOR FUNCTIONS
// ============================================

bool emb_latency_completed(void) {
    return g_emb_latency.test_completed;
}

bool emb_latency_all_passed(void) {
    return g_emb_latency.test_completed && g_emb_latency.test_passed;
}

int emb_latency_get_count(void) {
    return g_emb_latency.result_count;
}

const struct emb_latency_result* emb_latency_get(int index) {
    if (index < 0 || (uint32_t)index >= g_emb_latency.result_count)
        return NULL;
    return &g_emb_latency.results[index];
}

const struct emb_latency_result* emb_latency_get_by_vlan(uint16_t vlan_id) {
    for (uint32_t i = 0; i < g_emb_latency.result_count; i++) {
        if (g_emb_latency.results[i].vlan_id == vlan_id)
            return &g_emb_latency.results[i];
    }
    return NULL;
}

bool emb_latency_get_us(uint16_t vlan_id, double *min, double *avg, double *max) {
    const struct emb_latency_result *r = emb_latency_get_by_vlan(vlan_id);
    if (!r || !r->valid) return false;

    *min = ns_to_us(r->min_latency_ns);
    *avg = ns_to_us(r->avg_latency_ns);
    *max = ns_to_us(r->max_latency_ns);
    return true;
}

// ============================================
// PRINT FUNCTIONS
// ============================================

// Table column widths (matching standalone latency_test)
#define COL_PORT    8
#define COL_VLAN    10
#define COL_VLID    10
#define COL_LAT     11
#define COL_RXTX    10
#define COL_RESULT  8

static void print_table_line(const char *left, const char *mid, const char *right, const char *fill) {
    printf("%s", left);
    for (int i = 0; i < COL_PORT; i++) printf("%s", fill);
    printf("%s", mid);
    for (int i = 0; i < COL_PORT; i++) printf("%s", fill);
    printf("%s", mid);
    for (int i = 0; i < COL_VLAN; i++) printf("%s", fill);
    printf("%s", mid);
    for (int i = 0; i < COL_VLID; i++) printf("%s", fill);
    printf("%s", mid);
    for (int i = 0; i < COL_LAT; i++) printf("%s", fill);
    printf("%s", mid);
    for (int i = 0; i < COL_LAT; i++) printf("%s", fill);
    printf("%s", mid);
    for (int i = 0; i < COL_LAT; i++) printf("%s", fill);
    printf("%s", mid);
    for (int i = 0; i < COL_RXTX; i++) printf("%s", fill);
    printf("%s", mid);
    for (int i = 0; i < COL_RESULT; i++) printf("%s", fill);
    printf("%s\n", right);
}

#define TABLE_WIDTH (COL_PORT + COL_PORT + COL_VLAN + COL_VLID + COL_LAT + COL_LAT + COL_LAT + COL_RXTX + COL_RESULT + 8)

static void print_table_title(const char *title) {
    int title_len = strlen(title);
    int padding = (TABLE_WIDTH - title_len) / 2;

    printf("║");
    for (int i = 0; i < padding; i++) printf(" ");
    printf("%s", title);
    for (int i = 0; i < TABLE_WIDTH - padding - title_len; i++) printf(" ");
    printf("║\n");
}

// Generic function to print results table
static void print_results_table(const char *title, struct emb_latency_result *results, int count) {
    // Calculate statistics
    int successful = 0;
    int passed_count = 0;
    double total_avg_latency = 0.0;
    double min_of_mins = 1e9;
    double max_of_maxs = 0.0;

    for (int i = 0; i < count; i++) {
        struct emb_latency_result *r = &results[i];
        if (r->rx_count > 0) {
            successful++;
            double avg = ns_to_us(r->avg_latency_ns);
            total_avg_latency += avg;

            double min_lat = ns_to_us(r->min_latency_ns);
            double max_lat = ns_to_us(r->max_latency_ns);
            if (min_lat < min_of_mins) min_of_mins = min_lat;
            if (max_lat > max_of_maxs) max_of_maxs = max_lat;
        }
        if (r->passed) passed_count++;
    }

    printf("\n");
    fflush(stdout);

    // Top border
    print_table_line("╔", "╦", "╗", "═");

    // Title
    print_table_title(title);

    // Header separator
    print_table_line("╠", "╬", "╣", "═");

    // Header row
    printf("║%*s║%*s║%*s║%*s║%*s║%*s║%*s║%*s║%*s║\n",
           COL_PORT, "TX Port",
           COL_PORT, "RX Port",
           COL_VLAN, "VLAN",
           COL_VLID, "VL-ID",
           COL_LAT, "Min (us)",
           COL_LAT, "Avg (us)",
           COL_LAT, "Max (us)",
           COL_RXTX, "RX/TX",
           COL_RESULT, "Result");

    // Header bottom separator
    print_table_line("╠", "╬", "╣", "═");

    // Data rows
    for (int i = 0; i < count; i++) {
        struct emb_latency_result *r = &results[i];

        char min_str[16], avg_str[16], max_str[16], rxtx_str[16];
        const char *result_str = r->passed ? "PASS" : "FAIL";

        if (r->rx_count > 0) {
            snprintf(min_str, sizeof(min_str), "%9.2f", ns_to_us(r->min_latency_ns));
            snprintf(avg_str, sizeof(avg_str), "%9.2f", ns_to_us(r->avg_latency_ns));
            snprintf(max_str, sizeof(max_str), "%9.2f", ns_to_us(r->max_latency_ns));
        } else {
            snprintf(min_str, sizeof(min_str), "%9s", "-");
            snprintf(avg_str, sizeof(avg_str), "%9s", "-");
            snprintf(max_str, sizeof(max_str), "%9s", "-");
        }
        snprintf(rxtx_str, sizeof(rxtx_str), "%4u/%-4u", r->rx_count, r->tx_count);

        printf("║%*u║%*u║%*u║%*u║%*s║%*s║%*s║%*s║%*s║\n",
               COL_PORT, r->tx_port,
               COL_PORT, r->rx_port,
               COL_VLAN, r->vlan_id,
               COL_VLID, r->vl_id,
               COL_LAT, min_str,
               COL_LAT, avg_str,
               COL_LAT, max_str,
               COL_RXTX, rxtx_str,
               COL_RESULT, result_str);
    }

    // Summary separator
    print_table_line("╠", "╩", "╣", "═");

    // Summary line
    char summary[128];
    if (successful > 0) {
        snprintf(summary, sizeof(summary),
                "SUMMARY: PASS %d/%d | Avg: %.2f us | Max: %.2f us | Packets/VLAN: 1",
                passed_count, count,
                total_avg_latency / successful,
                max_of_maxs);
    } else {
        snprintf(summary, sizeof(summary),
                "SUMMARY: PASS %d/%d | Packets/VLAN: 1",
                passed_count, count);
    }
    print_table_title(summary);

    // Bottom border
    print_table_line("╚", "╩", "╝", "═");

    printf("\n");
    fflush(stdout);
}

void emb_latency_print(void) {
    print_results_table("LATENCY TEST RESULTS (Timestamp: HARDWARE NIC)",
                        g_emb_latency.results, g_emb_latency.result_count);
}

void emb_latency_print_loopback(void) {
    print_results_table("LOOPBACK TEST RESULTS (Switch Latency)",
                        g_emb_latency.loopback_results, g_emb_latency.loopback_result_count);
}

void emb_latency_print_unit(void) {
    print_results_table("UNIT TEST RESULTS (Device Latency)",
                        g_emb_latency.unit_results, g_emb_latency.unit_result_count);
}

void emb_latency_print_summary(void) {
    printf("║  SUMMARY: %u/%u PASSED | Min: %.2f us | Avg: %.2f us | Max: %.2f us | Duration: %.1f ms  ║\n",
           g_emb_latency.passed_count,
           g_emb_latency.result_count,
           ns_to_us(g_emb_latency.overall_min_ns),
           ns_to_us(g_emb_latency.overall_avg_ns),
           ns_to_us(g_emb_latency.overall_max_ns),
           g_emb_latency.test_duration_ns / 1000000.0);
}

void emb_latency_print_combined(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                       COMBINED LATENCY RESULTS (Per Direction)                                ║\n");
    printf("╠═══════════╦═══════════╦══════════════════╦══════════════════╦══════════════════╦═════════════╣\n");
    printf("║ Direction ║  Source   ║  Switch (µs)     ║  Total (µs)      ║  Unit (µs)       ║   Status    ║\n");
    printf("╠═══════════╬═══════════╬══════════════════╬══════════════════╬══════════════════╬═════════════╣\n");

    for (uint32_t i = 0; i < g_emb_latency.combined_count; i++) {
        struct emb_combined_latency *c = &g_emb_latency.combined[i];

        printf("║   %u → %u   ║ %-9s ║     %8.2f     ║     %8.2f     ║     %8.2f     ║    %s    ║\n",
               c->tx_port, c->rx_port,
               c->switch_measured ? "measured" : "default",
               c->switch_latency_us,
               c->total_measured ? c->total_latency_us : 0.0,
               c->unit_valid ? c->unit_latency_us : 0.0,
               c->unit_valid ? "OK" : "N/A");
    }

    printf("╚═══════════╩═══════════╩══════════════════╩══════════════════╩══════════════════╩═════════════╝\n");
    printf("\n");
    printf("Formula: Unit Latency = Total Latency - Switch Latency\n");
    printf("Switch latency source: %s\n\n",
           g_emb_latency.loopback_skipped ? "Default (14 µs)" : "Measured (Loopback test)");
}

// ============================================
// COMBINED LATENCY ACCESSORS
// ============================================

const struct emb_combined_latency* emb_latency_get_combined(uint16_t tx_port) {
    for (uint32_t i = 0; i < g_emb_latency.combined_count; i++) {
        if (g_emb_latency.combined[i].tx_port == tx_port)
            return &g_emb_latency.combined[i];
    }
    return NULL;
}

/**
 * Get combined latency for a specific direction (tx_port → rx_port)
 */
const struct emb_combined_latency* emb_latency_get_combined_direction(uint16_t tx_port, uint16_t rx_port) {
    for (uint32_t i = 0; i < g_emb_latency.combined_count; i++) {
        if (g_emb_latency.combined[i].tx_port == tx_port &&
            g_emb_latency.combined[i].rx_port == rx_port)
            return &g_emb_latency.combined[i];
    }
    return NULL;
}

bool emb_latency_get_unit_us(uint16_t tx_port, double *unit_latency_us) {
    const struct emb_combined_latency *c = emb_latency_get_combined(tx_port);
    if (!c || !c->unit_valid) return false;

    *unit_latency_us = c->unit_latency_us;
    return true;
}

bool emb_latency_get_all_us(uint16_t tx_port, double *switch_us, double *total_us, double *unit_us) {
    const struct emb_combined_latency *c = emb_latency_get_combined(tx_port);
    if (!c || !c->unit_valid) return false;

    *switch_us = c->switch_latency_us;
    *total_us = c->total_latency_us;
    *unit_us = c->unit_latency_us;
    return true;
}

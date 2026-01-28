#define _GNU_SOURCE
#include "raw_socket_port.h"
#include "packet.h"
#include "dpdk_external_tx.h"
#include "socket.h"  // for get_unused_cores()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sched.h>
#include <x86intrin.h>  // for _mm_pause()
#include <stdatomic.h>  // for atomic operations

// ==========================================
// GLOBAL VARIABLES
// ==========================================

struct raw_socket_port raw_ports[MAX_RAW_SOCKET_PORTS];
struct raw_socket_port_config raw_port_configs[MAX_RAW_SOCKET_PORTS] = RAW_SOCKET_PORTS_CONFIG_INIT;

static volatile bool *g_stop_flag = NULL;

// ==========================================
// GLOBAL SEQUENCE TRACKING (shared across all RX queues)
// ==========================================
// Bu yapı tüm multi-queue RX thread'leri tarafından paylaşılır.
// PACKET_FANOUT_HASH aynı VL-ID'yi farklı queue'lara dağıtabildiği için
// global tracking gerekli.

// Port 12: VL-ID 4291-4418 (from Port 2,3,4,5)
#define GLOBAL_SEQ_VL_ID_START_P12 4291
#define GLOBAL_SEQ_VL_ID_COUNT_P12 128

// Port 13: VL-ID 4099-4130 (from Port 0,6)
#define GLOBAL_SEQ_VL_ID_START_P13 4099
#define GLOBAL_SEQ_VL_ID_COUNT_P13 32

// Legacy defines for backward compatibility
#define GLOBAL_SEQ_VL_ID_START GLOBAL_SEQ_VL_ID_START_P12
#define GLOBAL_SEQ_VL_ID_COUNT GLOBAL_SEQ_VL_ID_COUNT_P12

struct global_vl_seq_state {
    _Atomic uint64_t min_seq;      // İlk görülen sequence
    _Atomic uint64_t max_seq;      // En yüksek sequence
    _Atomic uint64_t rx_count;     // Alınan paket sayısı
    _Atomic bool initialized;      // İlk paket alındı mı?
};

static struct global_vl_seq_state g_vl_seq_p12[GLOBAL_SEQ_VL_ID_COUNT_P12];
static struct global_vl_seq_state g_vl_seq_p13[GLOBAL_SEQ_VL_ID_COUNT_P13];
// Legacy alias
#define g_vl_seq g_vl_seq_p12
static _Atomic bool g_seq_tracking_reset = false;

// Reset global sequence tracking (call before starting a new test)
void reset_global_sequence_tracking(void)
{
    // Reset Port 12 tracking
    for (int i = 0; i < GLOBAL_SEQ_VL_ID_COUNT_P12; i++) {
        atomic_store(&g_vl_seq_p12[i].min_seq, UINT64_MAX);
        atomic_store(&g_vl_seq_p12[i].max_seq, 0);
        atomic_store(&g_vl_seq_p12[i].rx_count, 0);
        atomic_store(&g_vl_seq_p12[i].initialized, false);
    }
    // Reset Port 13 tracking
    for (int i = 0; i < GLOBAL_SEQ_VL_ID_COUNT_P13; i++) {
        atomic_store(&g_vl_seq_p13[i].min_seq, UINT64_MAX);
        atomic_store(&g_vl_seq_p13[i].max_seq, 0);
        atomic_store(&g_vl_seq_p13[i].rx_count, 0);
        atomic_store(&g_vl_seq_p13[i].initialized, false);
    }
    atomic_store(&g_seq_tracking_reset, false);
}

// Get global sequence tracking lost count for Port 12
uint64_t get_global_sequence_lost(void)
{
    uint64_t total_lost = 0;
    for (int i = 0; i < GLOBAL_SEQ_VL_ID_COUNT_P12; i++) {
        if (atomic_load(&g_vl_seq_p12[i].initialized)) {
            uint64_t min_s = atomic_load(&g_vl_seq_p12[i].min_seq);
            uint64_t max_s = atomic_load(&g_vl_seq_p12[i].max_seq);
            uint64_t rx_cnt = atomic_load(&g_vl_seq_p12[i].rx_count);
            uint64_t expected = max_s - min_s + 1;
            if (expected > rx_cnt) {
                total_lost += (expected - rx_cnt);
            }
        }
    }
    return total_lost;
}

// Get global sequence tracking lost count for Port 13
uint64_t get_global_sequence_lost_p13(void)
{
    uint64_t total_lost = 0;
    for (int i = 0; i < GLOBAL_SEQ_VL_ID_COUNT_P13; i++) {
        if (atomic_load(&g_vl_seq_p13[i].initialized)) {
            uint64_t min_s = atomic_load(&g_vl_seq_p13[i].min_seq);
            uint64_t max_s = atomic_load(&g_vl_seq_p13[i].max_seq);
            uint64_t rx_cnt = atomic_load(&g_vl_seq_p13[i].rx_count);
            uint64_t expected = max_s - min_s + 1;
            if (expected > rx_cnt) {
                total_lost += (expected - rx_cnt);
            }
        }
    }
    return total_lost;
}

// Debug: Print per-VL-ID sequence statistics
void print_global_sequence_debug(void)
{
    printf("  Global Sequence Debug (first 5 active VL-IDs):\n");
    int printed = 0;
    int total_with_loss = 0;
    uint64_t max_loss_vlid = 0;
    int64_t max_loss = 0;

    for (int i = 0; i < GLOBAL_SEQ_VL_ID_COUNT; i++) {
        if (atomic_load(&g_vl_seq[i].initialized)) {
            uint64_t min_s = atomic_load(&g_vl_seq[i].min_seq);
            uint64_t max_s = atomic_load(&g_vl_seq[i].max_seq);
            uint64_t rx_cnt = atomic_load(&g_vl_seq[i].rx_count);
            uint64_t expected = max_s - min_s + 1;
            int64_t lost = (expected > rx_cnt) ? (expected - rx_cnt) : 0;

            if (printed < 5) {
                printf("    VL-ID %u: min=%lu max=%lu rx=%lu expected=%lu lost=%ld\n",
                       GLOBAL_SEQ_VL_ID_START + i, min_s, max_s, rx_cnt, expected, lost);
                printed++;
            }

            if (lost > 0) {
                total_with_loss++;
                if (lost > max_loss) {
                    max_loss = lost;
                    max_loss_vlid = GLOBAL_SEQ_VL_ID_START + i;
                }
            }
        }
    }

    if (printed == 0) {
        printf("    (no VL-IDs initialized yet)\n");
    }

    if (total_with_loss > 0) {
        printf("    ⚠️  %d VL-IDs have loss, worst: VL-ID %lu with %ld lost\n",
               total_with_loss, max_loss_vlid, max_loss);
    }
}

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint16_t calculate_ip_checksum_raw(const void *ip_header)
{
    const uint16_t *ptr = (const uint16_t *)ip_header;
    uint32_t sum = 0;

    for (int i = 0; i < 10; i++) {
        sum += ntohs(ptr[i]);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return htons(~sum & 0xFFFF);
}

// ==========================================
// RATE LIMITER FUNCTIONS
// ==========================================

void init_raw_rate_limiter(struct raw_rate_limiter *limiter, uint32_t rate_mbps)
{
    limiter->tokens_per_sec = (uint64_t)rate_mbps * 1000000ULL / 8ULL;
    // Larger bucket: 500ms worth of tokens for smoother high-rate operation
    limiter->max_tokens = limiter->tokens_per_sec / 2;

    uint64_t min_bucket = RAW_PKT_TOTAL_SIZE * 256;  // At least 256 packets
    if (limiter->max_tokens < min_bucket) {
        limiter->max_tokens = min_bucket;
    }

    // Start with full bucket
    limiter->tokens = limiter->max_tokens;
    limiter->last_update_ns = get_time_ns();

    // Disable smooth pacing by default (legacy mode)
    limiter->smooth_pacing_enabled = false;
    limiter->delay_ns = 0;
    limiter->next_send_time_ns = 0;
}

// Initialize rate limiter with smooth pacing (timestamp-based like DPDK)
void init_raw_rate_limiter_smooth(struct raw_rate_limiter *limiter, uint32_t rate_mbps,
                                   uint16_t target_id, uint16_t total_targets)
{
    // Also init token bucket as fallback
    limiter->tokens_per_sec = (uint64_t)rate_mbps * 1000000ULL / 8ULL;
    limiter->max_tokens = limiter->tokens_per_sec / 2000;  // 0.5ms burst (like DPDK)
    limiter->tokens = 0;  // Soft start
    limiter->last_update_ns = get_time_ns();

    // Calculate smooth pacing parameters
    // bytes_per_sec = rate_mbps * 1000000 / 8
    uint64_t bytes_per_sec = (uint64_t)rate_mbps * 125000ULL;
#if IMIX_ENABLED
    uint64_t packets_per_sec = bytes_per_sec / RAW_IMIX_AVG_PACKET_SIZE;
#else
    uint64_t packets_per_sec = bytes_per_sec / RAW_PKT_TOTAL_SIZE;
#endif

    if (packets_per_sec > 0) {
        // delay_ns = 1 second in ns / packets_per_sec
        limiter->delay_ns = 1000000000ULL / packets_per_sec;
    } else {
        limiter->delay_ns = 1000000000ULL;  // 1 second if rate is 0
    }

    // Stagger start time: Each target starts at different offset
    // This spreads traffic smoothly across all targets
    uint64_t stagger_interval_ns = 50000000ULL;  // 50ms per target
    uint64_t stagger_offset = (uint64_t)target_id * stagger_interval_ns;
    limiter->next_send_time_ns = get_time_ns() + stagger_offset;

    limiter->smooth_pacing_enabled = true;

    printf("[Raw Rate Limiter] Target %u: rate=%u Mbps, delay=%lu ns (%.2f us), "
           "pps=%lu, stagger=%lu ms\n",
           target_id, rate_mbps, limiter->delay_ns,
           (double)limiter->delay_ns / 1000.0,
           packets_per_sec, stagger_offset / 1000000);
}

// Check if it's time to send next packet (smooth pacing)
bool raw_check_smooth_pacing(struct raw_rate_limiter *limiter)
{
    if (!limiter->smooth_pacing_enabled) {
        return raw_consume_tokens(limiter, RAW_PKT_TOTAL_SIZE);
    }

    uint64_t now = get_time_ns();

    // Not time yet
    if (now < limiter->next_send_time_ns) {
        return false;
    }

    // If we're too far behind (>2ms), reset to now (prevents large burst)
    if (limiter->next_send_time_ns + 2000000ULL < now) {
        limiter->next_send_time_ns = now;
    }

    // Schedule next packet
    limiter->next_send_time_ns += limiter->delay_ns;

    return true;
}

static void update_raw_tokens(struct raw_rate_limiter *limiter)
{
    uint64_t now = get_time_ns();
    uint64_t elapsed_ns = now - limiter->last_update_ns;

    if (elapsed_ns == 0) return;

    // More precise calculation for high rates
    uint64_t tokens_to_add = (elapsed_ns * limiter->tokens_per_sec) / 1000000000ULL;

    // Only update last_update_ns when we actually add tokens
    // This prevents losing small time increments
    if (tokens_to_add > 0) {
        limiter->tokens += tokens_to_add;
        if (limiter->tokens > limiter->max_tokens) {
            limiter->tokens = limiter->max_tokens;
        }
        limiter->last_update_ns = now;
    }
}

bool raw_consume_tokens(struct raw_rate_limiter *limiter, uint64_t bytes)
{
    update_raw_tokens(limiter);

    if (limiter->tokens >= bytes) {
        limiter->tokens -= bytes;
        return true;
    }

    return false;
}

// ==========================================
// PRBS-31 CACHE INITIALIZATION
// ==========================================

#define PRBS31_TAP1 31
#define PRBS31_TAP2 28
#define RAW_PRBS_CACHE_SIZE (268435456)

static uint32_t prbs31_next(uint32_t state)
{
    uint32_t bit = ((state >> (PRBS31_TAP1 - 1)) ^ (state >> (PRBS31_TAP2 - 1))) & 1;
    return ((state << 1) | bit) & 0x7FFFFFFF;
}

int init_raw_prbs_cache(struct raw_socket_port *port)
{
    if (port->prbs_initialized) return 0;

    printf("[Raw Port %d] Initializing PRBS cache (~256MB)...\n", port->port_id);

    port->prbs_cache = aligned_alloc(4096, RAW_PRBS_CACHE_SIZE);
    if (!port->prbs_cache) {
        fprintf(stderr, "[Raw Port %d] Failed to allocate PRBS cache\n", port->port_id);
        return -1;
    }

    size_t ext_size = RAW_PRBS_CACHE_SIZE + RAW_PKT_PRBS_BYTES;
    port->prbs_cache_ext = aligned_alloc(4096, ext_size);
    if (!port->prbs_cache_ext) {
        fprintf(stderr, "[Raw Port %d] Failed to allocate PRBS cache ext\n", port->port_id);
        free(port->prbs_cache);
        return -1;
    }

    uint32_t state = 0x0000000F + port->port_id + 100;

    for (size_t i = 0; i < RAW_PRBS_CACHE_SIZE; i++) {
        uint8_t byte_val = 0;
        for (int b = 0; b < 8; b++) {
            state = prbs31_next(state);
            byte_val = (byte_val << 1) | (state & 1);
        }
        port->prbs_cache[i] = byte_val;
    }

    memcpy(port->prbs_cache_ext, port->prbs_cache, RAW_PRBS_CACHE_SIZE);
    memcpy(port->prbs_cache_ext + RAW_PRBS_CACHE_SIZE, port->prbs_cache, RAW_PKT_PRBS_BYTES);

    port->prbs_initialized = true;
    printf("[Raw Port %d] PRBS cache initialized\n", port->port_id);

    return 0;
}

// ==========================================
// PACKET BUILDING
// ==========================================

// Legacy build_raw_packet (sabit boyut için geriye uyumluluk)
int build_raw_packet(uint8_t *buffer, const uint8_t *src_mac,
                     uint16_t vl_id, uint64_t sequence, const uint8_t *prbs_data)
{
    static const uint8_t fixed_src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x20};
    (void)src_mac;

    // Ethernet Header
    buffer[0] = 0x03;
    buffer[1] = 0x00;
    buffer[2] = 0x00;
    buffer[3] = 0x00;
    buffer[4] = (vl_id >> 8) & 0xFF;
    buffer[5] = vl_id & 0xFF;
    memcpy(buffer + 6, fixed_src_mac, 6);
    buffer[12] = 0x08;
    buffer[13] = 0x00;

    // IPv4 Header
    uint8_t *ip = buffer + RAW_PKT_ETH_HDR_SIZE;
    ip[0] = 0x45;
    ip[1] = 0x00;
    uint16_t ip_total_len = RAW_PKT_IP_HDR_SIZE + RAW_PKT_UDP_HDR_SIZE + RAW_PKT_PAYLOAD_SIZE;
    ip[2] = (ip_total_len >> 8) & 0xFF;
    ip[3] = ip_total_len & 0xFF;
    ip[4] = 0x00;
    ip[5] = 0x00;
    ip[6] = 0x40;
    ip[7] = 0x00;
    ip[8] = 0x01;
    ip[9] = 0x11;
    ip[10] = 0x00;
    ip[11] = 0x00;
    ip[12] = 10;
    ip[13] = 0;
    ip[14] = 0;
    ip[15] = 0;
    ip[16] = 224;
    ip[17] = 224;
    ip[18] = (vl_id >> 8) & 0xFF;
    ip[19] = vl_id & 0xFF;

    uint16_t ip_checksum = calculate_ip_checksum_raw(ip);
    ip[10] = (ip_checksum >> 8) & 0xFF;
    ip[11] = ip_checksum & 0xFF;

    // UDP Header
    uint8_t *udp = ip + RAW_PKT_IP_HDR_SIZE;
    udp[0] = 0x00;
    udp[1] = 0x64;
    udp[2] = 0x00;
    udp[3] = 0x64;
    uint16_t udp_len = RAW_PKT_UDP_HDR_SIZE + RAW_PKT_PAYLOAD_SIZE;
    udp[4] = (udp_len >> 8) & 0xFF;
    udp[5] = udp_len & 0xFF;
    udp[6] = 0x00;
    udp[7] = 0x00;

    // Payload
    uint8_t *payload = udp + RAW_PKT_UDP_HDR_SIZE;
    memcpy(payload, &sequence, RAW_PKT_SEQ_BYTES);
    memcpy(payload + RAW_PKT_SEQ_BYTES, prbs_data, RAW_PKT_PRBS_BYTES);

    return RAW_PKT_TOTAL_SIZE;
}

#if IMIX_ENABLED
// IMIX: Dinamik boyutlu paket oluştur
int build_raw_packet_dynamic(uint8_t *buffer, const uint8_t *src_mac,
                              uint16_t vl_id, uint64_t sequence,
                              const uint8_t *prbs_data, uint16_t prbs_len,
                              uint16_t pkt_size)
{
    static const uint8_t fixed_src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x20};
    (void)src_mac;

    // Ethernet Header
    buffer[0] = 0x03;
    buffer[1] = 0x00;
    buffer[2] = 0x00;
    buffer[3] = 0x00;
    buffer[4] = (vl_id >> 8) & 0xFF;
    buffer[5] = vl_id & 0xFF;
    memcpy(buffer + 6, fixed_src_mac, 6);
    buffer[12] = 0x08;
    buffer[13] = 0x00;

    // IPv4 Header (dinamik total_length)
    uint8_t *ip = buffer + RAW_PKT_ETH_HDR_SIZE;
    uint16_t payload_size = pkt_size - RAW_PKT_ETH_HDR_SIZE - RAW_PKT_IP_HDR_SIZE - RAW_PKT_UDP_HDR_SIZE;
    uint16_t ip_total_len = RAW_PKT_IP_HDR_SIZE + RAW_PKT_UDP_HDR_SIZE + payload_size;

    ip[0] = 0x45;
    ip[1] = 0x00;
    ip[2] = (ip_total_len >> 8) & 0xFF;
    ip[3] = ip_total_len & 0xFF;
    ip[4] = 0x00;
    ip[5] = 0x00;
    ip[6] = 0x40;
    ip[7] = 0x00;
    ip[8] = 0x01;
    ip[9] = 0x11;
    ip[10] = 0x00;
    ip[11] = 0x00;
    ip[12] = 0x0A;
    ip[13] = 0x00;
    ip[14] = 0x00;
    ip[15] = 0x00;
    ip[16] = 0xE0;
    ip[17] = 0xE0;
    ip[18] = (vl_id >> 8) & 0xFF;
    ip[19] = vl_id & 0xFF;

    // IP Checksum
    uint16_t ip_checksum = calculate_ip_checksum_raw(ip);
    ip[10] = (ip_checksum >> 8) & 0xFF;
    ip[11] = ip_checksum & 0xFF;

    // UDP Header (dinamik dgram_len)
    uint8_t *udp = ip + RAW_PKT_IP_HDR_SIZE;
    udp[0] = 0x00;
    udp[1] = 0x64;
    udp[2] = 0x00;
    udp[3] = 0x64;
    uint16_t udp_len = RAW_PKT_UDP_HDR_SIZE + payload_size;
    udp[4] = (udp_len >> 8) & 0xFF;
    udp[5] = udp_len & 0xFF;
    udp[6] = 0x00;
    udp[7] = 0x00;

    // Payload (dinamik PRBS boyutu)
    uint8_t *payload = udp + RAW_PKT_UDP_HDR_SIZE;
    memcpy(payload, &sequence, RAW_PKT_SEQ_BYTES);
    memcpy(payload + RAW_PKT_SEQ_BYTES, prbs_data, prbs_len);

    return pkt_size;
}

// IMIX paket boyutu al (raw socket için - VLAN'sız)
static inline uint16_t get_raw_imix_packet_size(uint64_t pkt_counter, uint8_t worker_offset)
{
    static const uint16_t raw_imix_pattern[IMIX_PATTERN_SIZE] = RAW_IMIX_PATTERN_INIT;
    return raw_imix_pattern[(pkt_counter + worker_offset) % IMIX_PATTERN_SIZE];
}

// Raw IMIX PRBS boyutu hesapla
static inline uint16_t calc_raw_prbs_size(uint16_t pkt_size)
{
    return pkt_size - RAW_PKT_ETH_HDR_SIZE - RAW_PKT_IP_HDR_SIZE - RAW_PKT_UDP_HDR_SIZE - RAW_PKT_SEQ_BYTES;
}
#endif /* IMIX_ENABLED */

// ==========================================
// SOCKET INITIALIZATION
// ==========================================

static int get_interface_index(const char *if_name)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return ifr.ifr_ifindex;
}

static int get_interface_mac(const char *if_name, uint8_t *mac)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

int setup_raw_tx_ring(struct raw_socket_port *port)
{
    port->tx_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (port->tx_socket < 0) {
        fprintf(stderr, "[Raw Port %d] Failed to create TX socket: %s\n",
                port->port_id, strerror(errno));
        return -1;
    }

    int version = TPACKET_V2;
    if (setsockopt(port->tx_socket, SOL_PACKET, PACKET_VERSION,
                   &version, sizeof(version)) < 0) {
        fprintf(stderr, "[Raw Port %d] Failed to set TPACKET_V2: %s\n",
                port->port_id, strerror(errno));
        close(port->tx_socket);
        return -1;
    }

    struct tpacket_req req = {0};
    req.tp_block_size = RAW_SOCKET_RING_BLOCK_SIZE;
    req.tp_block_nr = RAW_SOCKET_RING_BLOCK_NR;
    req.tp_frame_size = RAW_SOCKET_RING_FRAME_SIZE;
    req.tp_frame_nr = RAW_SOCKET_RING_FRAME_NR;

    if (setsockopt(port->tx_socket, SOL_PACKET, PACKET_TX_RING,
                   &req, sizeof(req)) < 0) {
        fprintf(stderr, "[Raw Port %d] Failed to setup TX ring: %s\n",
                port->port_id, strerror(errno));
        close(port->tx_socket);
        return -1;
    }

    port->tx_ring_size = req.tp_block_size * req.tp_block_nr;
    port->tx_ring = mmap(NULL, port->tx_ring_size,
                         PROT_READ | PROT_WRITE, MAP_SHARED,
                         port->tx_socket, 0);
    if (port->tx_ring == MAP_FAILED) {
        fprintf(stderr, "[Raw Port %d] Failed to mmap TX ring: %s\n",
                port->port_id, strerror(errno));
        close(port->tx_socket);
        return -1;
    }

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = port->if_index;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(port->tx_socket, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "[Raw Port %d] Failed to bind TX socket: %s\n",
                port->port_id, strerror(errno));
        munmap(port->tx_ring, port->tx_ring_size);
        close(port->tx_socket);
        return -1;
    }

    port->tx_ring_offset = 0;
    printf("[Raw Port %d] TX ring ready (%zu KB)\n", port->port_id, port->tx_ring_size / 1024);
    return 0;
}

int setup_raw_rx_ring(struct raw_socket_port *port)
{
    port->rx_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (port->rx_socket < 0) {
        fprintf(stderr, "[Raw Port %d] Failed to create RX socket: %s\n",
                port->port_id, strerror(errno));
        return -1;
    }

    int version = TPACKET_V2;
    if (setsockopt(port->rx_socket, SOL_PACKET, PACKET_VERSION,
                   &version, sizeof(version)) < 0) {
        fprintf(stderr, "[Raw Port %d] Failed to set TPACKET_V2 for RX: %s\n",
                port->port_id, strerror(errno));
        close(port->rx_socket);
        return -1;
    }

    struct tpacket_req req = {0};
    req.tp_block_size = RAW_SOCKET_RING_BLOCK_SIZE;
    req.tp_block_nr = RAW_SOCKET_RING_BLOCK_NR;
    req.tp_frame_size = RAW_SOCKET_RING_FRAME_SIZE;
    req.tp_frame_nr = RAW_SOCKET_RING_FRAME_NR;

    if (setsockopt(port->rx_socket, SOL_PACKET, PACKET_RX_RING,
                   &req, sizeof(req)) < 0) {
        fprintf(stderr, "[Raw Port %d] Failed to setup RX ring: %s\n",
                port->port_id, strerror(errno));
        close(port->rx_socket);
        return -1;
    }

    port->rx_ring_size = req.tp_block_size * req.tp_block_nr;
    port->rx_ring = mmap(NULL, port->rx_ring_size,
                         PROT_READ | PROT_WRITE, MAP_SHARED,
                         port->rx_socket, 0);
    if (port->rx_ring == MAP_FAILED) {
        fprintf(stderr, "[Raw Port %d] Failed to mmap RX ring: %s\n",
                port->port_id, strerror(errno));
        close(port->rx_socket);
        return -1;
    }

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = port->if_index;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(port->rx_socket, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "[Raw Port %d] Failed to bind RX socket: %s\n",
                port->port_id, strerror(errno));
        munmap(port->rx_ring, port->rx_ring_size);
        close(port->rx_socket);
        return -1;
    }

    struct packet_mreq mreq = {0};
    mreq.mr_ifindex = port->if_index;
    mreq.mr_type = PACKET_MR_PROMISC;
    setsockopt(port->rx_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    port->rx_ring_offset = 0;
    printf("[Raw Port %d] RX ring ready (%zu KB)\n", port->port_id, port->rx_ring_size / 1024);
    return 0;
}

// ==========================================
// MULTI-QUEUE RX SETUP (PACKET_FANOUT)
// ==========================================

int setup_multi_queue_rx(struct raw_socket_port *port)
{
    // Determine queue count based on port type
    int target_queue_count = (port->port_id == 12) ? PORT_12_RX_QUEUE_COUNT : PORT_13_RX_QUEUE_COUNT;

    printf("\n=== Setting up Multi-Queue RX for Port %u ===\n", port->port_id);
    printf("  Target queue count: %d\n", target_queue_count);

    // Get unused CPU cores for RX queues
    int cores_found = get_unused_cores(target_queue_count, port->rx_cpu_cores);
    if (cores_found < target_queue_count) {
        fprintf(stderr, "[Port %u] Warning: Only %d cores available for %d RX queues\n",
                port->port_id, cores_found, target_queue_count);
    }
    port->rx_queue_count = cores_found > 0 ? cores_found : target_queue_count;

    // Create sockets and setup PACKET_FANOUT for load distribution
    for (int q = 0; q < port->rx_queue_count; q++) {
        struct raw_rx_queue *queue = &port->rx_queues[q];

        queue->queue_id = q;
        queue->cpu_core = (q < cores_found) ? port->rx_cpu_cores[q] : 0;
        queue->running = false;
        queue->rx_packets = 0;
        queue->rx_bytes = 0;
        queue->good_pkts = 0;
        queue->bad_pkts = 0;
        queue->bit_errors = 0;
        queue->lost_pkts = 0;

        // Create raw socket
        queue->socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (queue->socket_fd < 0) {
            fprintf(stderr, "[Port %u Q%d] Failed to create socket: %s\n",
                    port->port_id, q, strerror(errno));
            return -1;
        }

        // Set TPACKET_V2
        int version = TPACKET_V2;
        if (setsockopt(queue->socket_fd, SOL_PACKET, PACKET_VERSION,
                       &version, sizeof(version)) < 0) {
            fprintf(stderr, "[Port %u Q%d] Failed to set TPACKET_V2: %s\n",
                    port->port_id, q, strerror(errno));
            close(queue->socket_fd);
            return -1;
        }

        // Setup RX ring buffer
        struct tpacket_req req = {0};
        req.tp_block_size = RAW_SOCKET_RING_BLOCK_SIZE;
        req.tp_block_nr = RAW_SOCKET_RING_BLOCK_NR;
        req.tp_frame_size = RAW_SOCKET_RING_FRAME_SIZE;
        req.tp_frame_nr = RAW_SOCKET_RING_FRAME_NR;

        if (setsockopt(queue->socket_fd, SOL_PACKET, PACKET_RX_RING,
                       &req, sizeof(req)) < 0) {
            fprintf(stderr, "[Port %u Q%d] Failed to setup RX ring: %s\n",
                    port->port_id, q, strerror(errno));
            close(queue->socket_fd);
            return -1;
        }

        queue->ring_size = req.tp_block_size * req.tp_block_nr;
        queue->ring = mmap(NULL, queue->ring_size,
                           PROT_READ | PROT_WRITE, MAP_SHARED,
                           queue->socket_fd, 0);
        if (queue->ring == MAP_FAILED) {
            fprintf(stderr, "[Port %u Q%d] Failed to mmap ring: %s\n",
                    port->port_id, q, strerror(errno));
            close(queue->socket_fd);
            return -1;
        }

        // Bind to interface
        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = port->if_index;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(queue->socket_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            fprintf(stderr, "[Port %u Q%d] Failed to bind: %s\n",
                    port->port_id, q, strerror(errno));
            munmap(queue->ring, queue->ring_size);
            close(queue->socket_fd);
            return -1;
        }

        // Setup PACKET_FANOUT for load distribution across queues
        // PACKET_FANOUT_HASH distributes based on packet hash (src/dst IP+port)
        // Use port_id in group ID to ensure each port has unique fanout group
        uint16_t fanout_group_id = (RAW_SOCKET_FANOUT_GROUP_ID + port->port_id) & 0xFFFF;
        int fanout_arg = fanout_group_id | (PACKET_FANOUT_HASH << 16);
        if (setsockopt(queue->socket_fd, SOL_PACKET, PACKET_FANOUT,
                       &fanout_arg, sizeof(fanout_arg)) < 0) {
            fprintf(stderr, "[Port %u Q%d] Failed to set PACKET_FANOUT: %s\n",
                    port->port_id, q, strerror(errno));
            // Continue without fanout - will still work but may have contention
        }

        // Set promiscuous mode
        struct packet_mreq mreq = {0};
        mreq.mr_ifindex = port->if_index;
        mreq.mr_type = PACKET_MR_PROMISC;
        setsockopt(queue->socket_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

        queue->ring_offset = 0;
        printf("  Queue %d: socket=%d, ring=%zu KB, CPU core=%u\n",
               q, queue->socket_fd, queue->ring_size / 1024, queue->cpu_core);
    }

    port->use_multi_queue_rx = true;
    printf("=== Multi-Queue RX Setup Complete ===\n");
    return 0;
}

// ==========================================
// PORT INITIALIZATION
// ==========================================

int init_raw_socket_port(int raw_index, const struct raw_socket_port_config *config)
{
    struct raw_socket_port *port = &raw_ports[raw_index];

    memset(port, 0, sizeof(*port));
    port->raw_index = raw_index;
    port->port_id = config->port_id;
    port->config = *config;
    port->tx_socket = -1;
    port->rx_socket = -1;

    printf("\n=== Initializing Raw Socket Port %u (index %d) ===\n", config->port_id, raw_index);
    printf("  Interface: %s (%s)\n", config->interface_name, config->is_1g_port ? "1G" : "100M");
    printf("  TX Targets: %u\n", config->tx_target_count);

    for (int t = 0; t < config->tx_target_count; t++) {
        printf("    Target %d: -> Port %u, %u Mbps, VL-ID %u-%u (%u)\n",
               t, config->tx_targets[t].dest_port,
               config->tx_targets[t].rate_mbps,
               config->tx_targets[t].vl_id_start,
               config->tx_targets[t].vl_id_start + config->tx_targets[t].vl_id_count - 1,
               config->tx_targets[t].vl_id_count);
    }

    printf("  RX Sources: %u\n", config->rx_source_count);
    for (int s = 0; s < config->rx_source_count; s++) {
        printf("    Source %d: <- Port %u, VL-ID %u-%u (%u)\n",
               s, config->rx_sources[s].source_port,
               config->rx_sources[s].vl_id_start,
               config->rx_sources[s].vl_id_start + config->rx_sources[s].vl_id_count - 1,
               config->rx_sources[s].vl_id_count);
    }

    // Get interface index
    port->if_index = get_interface_index(config->interface_name);
    if (port->if_index < 0) {
        fprintf(stderr, "[Port %u] Interface not found: %s\n",
                config->port_id, config->interface_name);
        return -1;
    }

    // Get MAC address
    if (get_interface_mac(config->interface_name, port->mac_addr) < 0) {
        fprintf(stderr, "[Port %u] Failed to get MAC address\n", config->port_id);
        return -1;
    }

    printf("  MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           port->mac_addr[0], port->mac_addr[1], port->mac_addr[2],
           port->mac_addr[3], port->mac_addr[4], port->mac_addr[5]);

    // Initialize TX targets
    port->tx_target_count = config->tx_target_count;
    for (int t = 0; t < config->tx_target_count; t++) {
        struct raw_tx_target_state *target = &port->tx_targets[t];
        target->config = config->tx_targets[t];
        target->current_vl_offset = 0;

        // Initialize rate limiter with smooth pacing (timestamp-based like DPDK)
        init_raw_rate_limiter_smooth(&target->limiter, target->config.rate_mbps,
                                      t, config->tx_target_count);

        // Allocate VL-ID sequence trackers
        target->vl_sequences = calloc(target->config.vl_id_count, sizeof(struct raw_vl_sequence));
        if (!target->vl_sequences) {
            fprintf(stderr, "[Port %u] Failed to allocate TX VL sequences for target %d\n",
                    config->port_id, t);
            return -1;
        }

        for (uint16_t i = 0; i < target->config.vl_id_count; i++) {
            pthread_spin_init(&target->vl_sequences[i].tx_lock, PTHREAD_PROCESS_PRIVATE);
            pthread_spin_init(&target->vl_sequences[i].rx_lock, PTHREAD_PROCESS_PRIVATE);
        }

        pthread_spin_init(&target->stats.lock, PTHREAD_PROCESS_PRIVATE);
    }

    // Initialize RX sources
    port->rx_source_count = config->rx_source_count;
    for (int s = 0; s < config->rx_source_count; s++) {
        struct raw_rx_source_state *source = &port->rx_sources[s];
        source->config = config->rx_sources[s];

        // Allocate VL-ID sequence trackers
        source->vl_sequences = calloc(source->config.vl_id_count, sizeof(struct raw_vl_sequence));
        if (!source->vl_sequences) {
            fprintf(stderr, "[Port %u] Failed to allocate RX VL sequences for source %d\n",
                    config->port_id, s);
            return -1;
        }

        for (uint16_t i = 0; i < source->config.vl_id_count; i++) {
            pthread_spin_init(&source->vl_sequences[i].tx_lock, PTHREAD_PROCESS_PRIVATE);
            pthread_spin_init(&source->vl_sequences[i].rx_lock, PTHREAD_PROCESS_PRIVATE);
        }

        pthread_spin_init(&source->stats.lock, PTHREAD_PROCESS_PRIVATE);
    }

    // Initialize DPDK External RX stats (separate from raw socket sources)
    memset(&port->dpdk_ext_rx_stats, 0, sizeof(port->dpdk_ext_rx_stats));
    pthread_spin_init(&port->dpdk_ext_rx_stats.lock, PTHREAD_PROCESS_PRIVATE);

    // Setup TX ring
    if (setup_raw_tx_ring(port) < 0) return -1;

    // Setup RX - multi-queue for Port 12 and Port 13
    // Port 12: Multi-queue RX for high throughput DPDK external packets
    // Port 13: Multi-queue RX for better packet distribution
    printf("[Port %u] Setting up multi-queue RX (PACKET_FANOUT)\n", port->port_id);
    if (setup_multi_queue_rx(port) < 0) {
        fprintf(stderr, "[Port %u] Failed to setup multi-queue RX, falling back to single queue\n",
                port->port_id);
        // Fallback to single queue
        if (setup_raw_rx_ring(port) < 0) {
            munmap(port->tx_ring, port->tx_ring_size);
            close(port->tx_socket);
            return -1;
        }
    }

    // Initialize PRBS cache
    if (init_raw_prbs_cache(port) < 0) {
        munmap(port->tx_ring, port->tx_ring_size);
        if (port->use_multi_queue_rx) {
            stop_multi_queue_rx_workers(port);  // Cleanup multi-queue
        } else {
            munmap(port->rx_ring, port->rx_ring_size);
            close(port->rx_socket);
        }
        close(port->tx_socket);
        return -1;
    }

    printf("[Port %u] Initialization complete%s\n", port->port_id,
           port->use_multi_queue_rx ? " (multi-queue RX)" : "");
    return 0;
}

int init_raw_socket_ports(void)
{
    printf("\n=== Initializing Raw Socket Ports (Multi-Target) ===\n");

    // Initialize global sequence tracking (sets min_seq to UINT64_MAX)
    reset_global_sequence_tracking();

    for (int i = 0; i < MAX_RAW_SOCKET_PORTS; i++) {
        if (init_raw_socket_port(i, &raw_port_configs[i]) < 0) {
            fprintf(stderr, "Failed to initialize raw socket port %u\n",
                    raw_port_configs[i].port_id);
            return -1;
        }
    }

    printf("\n=== All Raw Socket Ports Initialized ===\n");
    return 0;
}

// ==========================================
// TX WORKER (Multi-Target with Smooth Pacing)
// ==========================================

void *raw_tx_worker(void *arg)
{
    struct raw_socket_port *port = (struct raw_socket_port *)arg;
    uint8_t packet_buffer[RAW_PKT_TOTAL_SIZE];  // Max boyut
    bool first_tx[MAX_RAW_TARGETS] = {false};

#if IMIX_ENABLED
    // IMIX: Worker offset (her target için farklı pattern başlangıcı)
    uint8_t imix_offset = (uint8_t)(port->port_id % IMIX_PATTERN_SIZE);
    uint64_t imix_counter = 0;
    printf("[Port %u TX Worker] Started with %u targets (IMIX MODE + SMOOTH PACING)\n",
           port->port_id, port->tx_target_count);
    printf("[Port %u TX] IMIX pattern: 96, 196, 396, 796, 1196x3, 1514x3 (avg=%d bytes)\n",
           port->port_id, RAW_IMIX_AVG_PACKET_SIZE);
#else
    printf("[Port %u TX Worker] Started with %u targets (SMOOTH PACING)\n",
           port->port_id, port->tx_target_count);
#endif

    port->tx_running = true;

    // Print target info
    for (int t = 0; t < port->tx_target_count; t++) {
        struct raw_tx_target_state *target = &port->tx_targets[t];
        printf("[Port %u TX] Target %d: rate=%u Mbps, delay=%.2f us, dest_port=%u\n",
               port->port_id, t, target->config.rate_mbps,
               (double)target->limiter.delay_ns / 1000.0,
               target->config.dest_port);
    }

    uint32_t batch_count = 0;
    const uint32_t BATCH_SIZE = 64;  // Batch for kernel efficiency
    const uint32_t MAX_CATCHUP_PER_TARGET = 32;  // Max packets per target per iteration (catch-up limit)

    while (!port->stop_flag && (g_stop_flag == NULL || !*g_stop_flag)) {
        bool any_sent = false;

        // Smooth pacing: Check each target's timing
        for (int t = 0; t < port->tx_target_count; t++) {
            struct raw_tx_target_state *target = &port->tx_targets[t];
            uint32_t sent_this_target = 0;

            // Send all packets that are due (catch-up), limited to MAX_CATCHUP_PER_TARGET
            while (raw_check_smooth_pacing(&target->limiter) &&
                   sent_this_target < MAX_CATCHUP_PER_TARGET) {
                // Get current VL-ID
                uint16_t vl_id = target->config.vl_id_start + target->current_vl_offset;
                uint16_t vl_index = target->current_vl_offset;

                // Get next sequence (thread-safe)
                pthread_spin_lock(&target->vl_sequences[vl_index].tx_lock);
                uint64_t seq = target->vl_sequences[vl_index].tx_sequence++;
                pthread_spin_unlock(&target->vl_sequences[vl_index].tx_lock);

#if IMIX_ENABLED
                // IMIX: Paket boyutunu pattern'den al
                uint16_t pkt_size = get_raw_imix_packet_size(imix_counter, imix_offset);
                uint16_t prbs_len = calc_raw_prbs_size(pkt_size);
                imix_counter++;

                // IMIX: PRBS offset hesabı HEP MAX boyut ile yapılır
                uint64_t prbs_offset = (seq * (uint64_t)RAW_MAX_PRBS_BYTES) % RAW_PRBS_CACHE_SIZE;
                uint8_t *prbs_data = port->prbs_cache_ext + prbs_offset;

                // Build packet (dinamik boyut)
                build_raw_packet_dynamic(packet_buffer, port->mac_addr, vl_id, seq,
                                          prbs_data, prbs_len, pkt_size);
#else
                // Get PRBS data
                uint64_t prbs_offset = (seq * (uint64_t)RAW_PKT_PRBS_BYTES) % RAW_PRBS_CACHE_SIZE;
                uint8_t *prbs_data = port->prbs_cache_ext + prbs_offset;

                // Build packet
                build_raw_packet(packet_buffer, port->mac_addr, vl_id, seq, prbs_data);
                uint16_t pkt_size = RAW_PKT_TOTAL_SIZE;
#endif

                // Get TX frame from ring
                struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)(
                    (uint8_t *)port->tx_ring +
                    (port->tx_ring_offset * RAW_SOCKET_RING_FRAME_SIZE));

                // Wait for frame to be available
                int wait_count = 0;
                while (hdr->tp_status != TP_STATUS_AVAILABLE) {
                    if (port->stop_flag || (g_stop_flag && *g_stop_flag)) {
                        goto exit_tx;
                    }
                    // Flush pending packets if waiting
                    if (batch_count > 0) {
                        send(port->tx_socket, NULL, 0, 0);
                        batch_count = 0;
                    }
                    if (++wait_count > 100) {
                        struct pollfd pfd = {port->tx_socket, POLLOUT, 0};
                        poll(&pfd, 1, 1);
                        wait_count = 0;
                    }
                }

                // Copy packet to ring buffer (dinamik boyut)
                uint8_t *frame_data = (uint8_t *)hdr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
                memcpy(frame_data, packet_buffer, pkt_size);
                hdr->tp_len = pkt_size;
                hdr->tp_status = TP_STATUS_SEND_REQUEST;

                // Update stats
                pthread_spin_lock(&target->stats.lock);
                target->stats.tx_packets++;
                target->stats.tx_bytes += pkt_size;
                pthread_spin_unlock(&target->stats.lock);

                if (!first_tx[t]) {
                    printf("[Port %u TX] Target %d (->P%u): First packet VL-ID=%u Seq=%lu\n",
                           port->port_id, t, target->config.dest_port, vl_id, seq);
                    first_tx[t] = true;
                }

                // Advance ring offset
                port->tx_ring_offset = (port->tx_ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;

                // Round-robin through VL-IDs
                target->current_vl_offset = (target->current_vl_offset + 1) % target->config.vl_id_count;
                any_sent = true;
                batch_count++;
                sent_this_target++;

                // Flush batch periodically
                if (batch_count >= BATCH_SIZE) {
                    if (send(port->tx_socket, NULL, 0, 0) < 0) {
                        pthread_spin_lock(&target->stats.lock);
                        target->stats.tx_errors++;
                        pthread_spin_unlock(&target->stats.lock);
                    }
                    batch_count = 0;
                }
            }
        }

        // Flush any remaining packets
        if (batch_count > 0) {
            send(port->tx_socket, NULL, 0, 0);
            batch_count = 0;
        }

        if (!any_sent) {
            struct timespec ts = {0, 100};  // 100ns sleep (was 1µs)
            nanosleep(&ts, NULL);
        }
    }

exit_tx:
    // Flush remaining
    if (batch_count > 0) {
        send(port->tx_socket, NULL, 0, 0);
    }
    printf("[Port %u TX Worker] Stopped\n", port->port_id);
    port->tx_running = false;
    return NULL;
}

// ==========================================
// RX WORKER (Multi-Source)
// ==========================================

void *raw_rx_worker(void *arg)
{
    struct raw_socket_port *port = (struct raw_socket_port *)arg;
    bool first_rx[MAX_RAW_TARGETS] = {false};

    printf("[Port %u RX Worker] Started, expecting from %u sources\n",
           port->port_id, port->rx_source_count);

    port->rx_running = true;

    // Find partner port for PRBS verification
    struct raw_socket_port *partner = NULL;
    if (port->rx_source_count > 0) {
        uint16_t partner_port_id = port->rx_sources[0].config.source_port;
        for (int i = 0; i < MAX_RAW_SOCKET_PORTS; i++) {
            if (raw_ports[i].port_id == partner_port_id) {
                partner = &raw_ports[i];
                break;
            }
        }
    }

    // Pre-cache PRBS pointers for DPDK external TX ports
#if DPDK_EXT_TX_ENABLED
    // Port 12 receives from Port 2,3,4,5 (VL-ID 4291-4418)
    // Port 13 receives from Port 0,6 (VL-ID 4099-4130)
    uint8_t *dpdk_prbs_caches_port12[4] = {
        get_prbs_cache_ext_for_port(2),
        get_prbs_cache_ext_for_port(3),
        get_prbs_cache_ext_for_port(4),
        get_prbs_cache_ext_for_port(5)
    };
    uint8_t *dpdk_prbs_caches_port13[2] = {
        get_prbs_cache_ext_for_port(0),
        get_prbs_cache_ext_for_port(6)
    };

    // Sequence tracking - separate for Port 12 and Port 13
    // Port 12: VL-ID 4291-4418 (128 entries)
    // Port 13: VL-ID 4099-4130 (32 entries)
    #define DPDK_EXT_VL_ID_START_P12 4291
    #define DPDK_EXT_VL_ID_COUNT_P12 128
    #define DPDK_EXT_VL_ID_START_P13 4099
    #define DPDK_EXT_VL_ID_COUNT_P13 32
    static uint64_t dpdk_ext_expected_seq_p12[DPDK_EXT_VL_ID_COUNT_P12];
    static bool dpdk_ext_seq_initialized_p12[DPDK_EXT_VL_ID_COUNT_P12];
    static uint64_t dpdk_ext_expected_seq_p13[DPDK_EXT_VL_ID_COUNT_P13];
    static bool dpdk_ext_seq_initialized_p13[DPDK_EXT_VL_ID_COUNT_P13];
    static bool dpdk_ext_seq_arrays_cleared = false;

    if (!dpdk_ext_seq_arrays_cleared) {
        memset(dpdk_ext_expected_seq_p12, 0, sizeof(dpdk_ext_expected_seq_p12));
        memset(dpdk_ext_seq_initialized_p12, 0, sizeof(dpdk_ext_seq_initialized_p12));
        memset(dpdk_ext_expected_seq_p13, 0, sizeof(dpdk_ext_expected_seq_p13));
        memset(dpdk_ext_seq_initialized_p13, 0, sizeof(dpdk_ext_seq_initialized_p13));
        dpdk_ext_seq_arrays_cleared = true;
    }
#endif

    // Local counters for batch stats update (reduces spinlock overhead)
    uint64_t local_dpdk_rx_pkts = 0;
    uint64_t local_dpdk_rx_bytes = 0;
    uint64_t local_dpdk_good = 0;
    uint64_t local_dpdk_bad = 0;
    uint64_t local_dpdk_bit_errors = 0;
    uint64_t local_dpdk_lost = 0;
    const uint32_t STATS_FLUSH_INTERVAL = 1024;  // Flush every 1024 packets
    uint32_t empty_polls = 0;
    const uint32_t BUSY_POLL_COUNT = 64;  // Spin this many times before blocking poll

    while (!port->stop_flag && (g_stop_flag == NULL || !*g_stop_flag)) {
        struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)(
            (uint8_t *)port->rx_ring +
            (port->rx_ring_offset * RAW_SOCKET_RING_FRAME_SIZE));

        if (!(hdr->tp_status & TP_STATUS_USER)) {
            empty_polls++;
            // Busy poll for a while before blocking
            if (empty_polls < BUSY_POLL_COUNT) {
                _mm_pause();  // CPU hint for spin-wait
                continue;
            }
            // Flush local stats before blocking poll
            if (local_dpdk_rx_pkts > 0) {
                pthread_spin_lock(&port->dpdk_ext_rx_stats.lock);
                port->dpdk_ext_rx_stats.rx_packets += local_dpdk_rx_pkts;
                port->dpdk_ext_rx_stats.rx_bytes += local_dpdk_rx_bytes;
                port->dpdk_ext_rx_stats.good_pkts += local_dpdk_good;
                port->dpdk_ext_rx_stats.bad_pkts += local_dpdk_bad;
                port->dpdk_ext_rx_stats.bit_errors += local_dpdk_bit_errors;
                port->dpdk_ext_rx_stats.lost_pkts += local_dpdk_lost;
                pthread_spin_unlock(&port->dpdk_ext_rx_stats.lock);
                local_dpdk_rx_pkts = 0;
                local_dpdk_rx_bytes = 0;
                local_dpdk_good = 0;
                local_dpdk_bad = 0;
                local_dpdk_bit_errors = 0;
                local_dpdk_lost = 0;
            }
            struct pollfd pfd = {port->rx_socket, POLLIN, 0};
            poll(&pfd, 1, 1);  // 1ms blocking poll
            empty_polls = 0;
            continue;
        }
        empty_polls = 0;  // Reset on successful packet

        uint8_t *pkt_data = (uint8_t *)hdr + hdr->tp_mac;
        uint32_t pkt_len = hdr->tp_len;

        // Validate minimum packet size
        if (pkt_len < RAW_PKT_ETH_HDR_SIZE + RAW_PKT_IP_HDR_SIZE +
                      RAW_PKT_UDP_HDR_SIZE + RAW_PKT_SEQ_BYTES) {
            hdr->tp_status = TP_STATUS_KERNEL;
            port->rx_ring_offset = (port->rx_ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;
            continue;
        }

        // Check EtherType (must be IPv4 - VLAN is stripped by switch)
        uint16_t ethertype = (pkt_data[12] << 8) | pkt_data[13];
        if (ethertype != 0x0800) {
            hdr->tp_status = TP_STATUS_KERNEL;
            port->rx_ring_offset = (port->rx_ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;
            continue;
        }

        // Extract VL-ID from DST MAC
        uint16_t vl_id = ((uint16_t)pkt_data[4] << 8) | pkt_data[5];

        // ==========================================
        // DPDK EXTERNAL TX PACKET HANDLING
        // Switch strips VLAN header, so packets arrive as IPv4 (0x0800)
        // Port 12: VL-ID 4291-4418 from Port 2,3,4,5
        // Port 13: VL-ID 4099-4130 from Port 0,6
        // ==========================================
#if DPDK_EXT_TX_ENABLED
        int dpdk_src_port = dpdk_ext_tx_get_source_port(vl_id);
        if (dpdk_src_port >= 0) {
            // This is a DPDK external packet (VLAN stripped by switch)
            // Offsets for non-VLAN packet: ETH(14) + IP(20) + UDP(8) = 42
            uint8_t *payload = pkt_data + 14 + 20 + 8;
            uint64_t seq;
            memcpy(&seq, payload, sizeof(seq));

            // Update local stats (no spinlock per packet!)
            local_dpdk_rx_pkts++;
            local_dpdk_rx_bytes += pkt_len;

            // Sequence tracking for lost packet detection (port-specific)
            if (port->port_id == 12) {
                // Port 12 receives from Port 2,3,4,5
                uint16_t vl_idx = vl_id - DPDK_EXT_VL_ID_START_P12;
                if (vl_idx < DPDK_EXT_VL_ID_COUNT_P12) {
                    if (!dpdk_ext_seq_initialized_p12[vl_idx]) {
                        dpdk_ext_expected_seq_p12[vl_idx] = seq + 1;
                        dpdk_ext_seq_initialized_p12[vl_idx] = true;
                    } else {
                        uint64_t expected = dpdk_ext_expected_seq_p12[vl_idx];
                        if (seq > expected) {
                            local_dpdk_lost += (seq - expected);
                        }
                        dpdk_ext_expected_seq_p12[vl_idx] = seq + 1;
                    }
                }
            } else if (port->port_id == 13) {
                // Port 13 receives from Port 0,6
                uint16_t vl_idx = vl_id - DPDK_EXT_VL_ID_START_P13;
                if (vl_idx < DPDK_EXT_VL_ID_COUNT_P13) {
                    if (!dpdk_ext_seq_initialized_p13[vl_idx]) {
                        dpdk_ext_expected_seq_p13[vl_idx] = seq + 1;
                        dpdk_ext_seq_initialized_p13[vl_idx] = true;
                    } else {
                        uint64_t expected = dpdk_ext_expected_seq_p13[vl_idx];
                        if (seq > expected) {
                            local_dpdk_lost += (seq - expected);
                        }
                        dpdk_ext_expected_seq_p13[vl_idx] = seq + 1;
                    }
                }
            }

            // PRBS verification using pre-cached DPDK port's cache
            // Port 12: dpdk_src_port 2,3,4,5 → index 0,1,2,3
            // Port 13: dpdk_src_port 0,6 → index 0,1
            int cache_idx = -1;
            uint8_t *dpdk_prbs_cache = NULL;
            if (port->port_id == 12) {
                cache_idx = dpdk_src_port - 2;
                dpdk_prbs_cache = (cache_idx >= 0 && cache_idx < 4) ? dpdk_prbs_caches_port12[cache_idx] : NULL;
            } else if (port->port_id == 13) {
                if (dpdk_src_port == 0) cache_idx = 0;
                else if (dpdk_src_port == 6) cache_idx = 1;
                dpdk_prbs_cache = (cache_idx >= 0 && cache_idx < 2) ? dpdk_prbs_caches_port13[cache_idx] : NULL;
            }
            if (dpdk_prbs_cache) {
                uint8_t *recv_prbs = payload + 8;
                // DPDK TX uses NUM_PRBS_BYTES for both offset calculation and data
                // Must use NUM_PRBS_BYTES for offset calc to match TX side!
                uint16_t cmp_bytes = pkt_len - 14 - 20 - 8 - 8; // ETH+IP+UDP+SEQ
                if (cmp_bytes > NUM_PRBS_BYTES) cmp_bytes = NUM_PRBS_BYTES;

                // CRITICAL: Use NUM_PRBS_BYTES for offset, same as TX side
                uint64_t prbs_offset = (seq * (uint64_t)NUM_PRBS_BYTES) % PRBS_CACHE_SIZE;
                uint8_t *expected_prbs = dpdk_prbs_cache + prbs_offset;

                if (memcmp(recv_prbs, expected_prbs, cmp_bytes) == 0) {
                    local_dpdk_good++;
                } else {
                    static int debug_count = 0;
                    if (debug_count < 5) {
                        debug_count++;
                        // Get IP header info
                        uint8_t ip_ver_ihl = pkt_data[14];
                        uint8_t ip_ihl = (ip_ver_ihl & 0x0F) * 4;  // IP header length in bytes

                        printf("[DPDK-EXT RX DEBUG] PRBS Error #%d: VL-ID=%u, src_port=%d, seq=%lu, pkt_len=%u, cmp_bytes=%u\n",
                               debug_count, vl_id, dpdk_src_port, seq, pkt_len, cmp_bytes);
                        printf("  IP: ver_ihl=0x%02x (IHL=%u bytes), EtherType=0x%02x%02x\n",
                               ip_ver_ihl, ip_ihl, pkt_data[12], pkt_data[13]);
                        printf("  prbs_offset=%lu, NUM_PRBS_BYTES=%u, PRBS_CACHE_SIZE=%lu\n",
                               prbs_offset, NUM_PRBS_BYTES, (unsigned long)PRBS_CACHE_SIZE);
                        printf("  dpdk_prbs_cache=%p, expected_prbs=%p, recv_prbs=%p\n",
                               (void*)dpdk_prbs_cache, (void*)expected_prbs, (void*)recv_prbs);
                        printf("  recv[0..7]: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                               recv_prbs[0], recv_prbs[1], recv_prbs[2], recv_prbs[3],
                               recv_prbs[4], recv_prbs[5], recv_prbs[6], recv_prbs[7]);
                        printf("  exp[0..7]:  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                               expected_prbs[0], expected_prbs[1], expected_prbs[2], expected_prbs[3],
                               expected_prbs[4], expected_prbs[5], expected_prbs[6], expected_prbs[7]);
                    }
                    local_dpdk_bad++;
                    for (int b = 0; b < cmp_bytes; b++) {
                        local_dpdk_bit_errors += __builtin_popcount(recv_prbs[b] ^ expected_prbs[b]);
                    }
                }
            }

            // Periodic stats flush
            if (local_dpdk_rx_pkts >= STATS_FLUSH_INTERVAL) {
                pthread_spin_lock(&port->dpdk_ext_rx_stats.lock);
                port->dpdk_ext_rx_stats.rx_packets += local_dpdk_rx_pkts;
                port->dpdk_ext_rx_stats.rx_bytes += local_dpdk_rx_bytes;
                port->dpdk_ext_rx_stats.good_pkts += local_dpdk_good;
                port->dpdk_ext_rx_stats.bad_pkts += local_dpdk_bad;
                port->dpdk_ext_rx_stats.bit_errors += local_dpdk_bit_errors;
                port->dpdk_ext_rx_stats.lost_pkts += local_dpdk_lost;
                pthread_spin_unlock(&port->dpdk_ext_rx_stats.lock);
                local_dpdk_rx_pkts = 0;
                local_dpdk_rx_bytes = 0;
                local_dpdk_good = 0;
                local_dpdk_bad = 0;
                local_dpdk_bit_errors = 0;
                local_dpdk_lost = 0;
            }

            hdr->tp_status = TP_STATUS_KERNEL;
            port->rx_ring_offset = (port->rx_ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;
            continue;
        }
#endif

        // ==========================================
        // RAW SOCKET PACKET HANDLING (from Port 13)
        // ==========================================
        // Find which source this packet belongs to
        int source_idx = -1;
        for (int s = 0; s < port->rx_source_count; s++) {
            struct raw_rx_source_state *source = &port->rx_sources[s];
            if (vl_id >= source->config.vl_id_start &&
                vl_id < source->config.vl_id_start + source->config.vl_id_count) {
                source_idx = s;
                break;
            }
        }

        if (source_idx < 0) {
            // Not from a known source, skip
            hdr->tp_status = TP_STATUS_KERNEL;
            port->rx_ring_offset = (port->rx_ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;
            continue;
        }

        struct raw_rx_source_state *source = &port->rx_sources[source_idx];
        uint16_t vl_index = vl_id - source->config.vl_id_start;

        // Get sequence number from payload
        uint8_t *payload = pkt_data + RAW_PKT_ETH_HDR_SIZE + RAW_PKT_IP_HDR_SIZE + RAW_PKT_UDP_HDR_SIZE;
        uint64_t seq;
        memcpy(&seq, payload, sizeof(seq));

        pthread_spin_lock(&source->stats.lock);
        source->stats.rx_packets++;
        source->stats.rx_bytes += pkt_len;
        pthread_spin_unlock(&source->stats.lock);

        if (!first_rx[source_idx]) {
            printf("[Port %u RX] Source %d (<-P%u): First packet VL-ID=%u Seq=%lu\n",
                   port->port_id, source_idx, source->config.source_port, vl_id, seq);
            first_rx[source_idx] = true;
        }

        // Sequence validation
        pthread_spin_lock(&source->vl_sequences[vl_index].rx_lock);

        if (!source->vl_sequences[vl_index].rx_initialized) {
            source->vl_sequences[vl_index].rx_expected_seq = seq + 1;
            source->vl_sequences[vl_index].rx_initialized = true;
        } else {
            uint64_t expected = source->vl_sequences[vl_index].rx_expected_seq;

            if (seq != expected) {
                if (seq > expected) {
                    uint64_t gap = seq - expected;
                    pthread_spin_lock(&source->stats.lock);
                    source->stats.lost_pkts += gap;
                    pthread_spin_unlock(&source->stats.lock);
                } else {
                    pthread_spin_lock(&source->stats.lock);
                    if (seq == expected - 1) {
                        source->stats.duplicate_pkts++;
                    } else {
                        source->stats.out_of_order_pkts++;
                    }
                    pthread_spin_unlock(&source->stats.lock);
                }
            }

            source->vl_sequences[vl_index].rx_expected_seq = seq + 1;
        }

        pthread_spin_unlock(&source->vl_sequences[vl_index].rx_lock);

        // PRBS verification
        if (partner && partner->prbs_initialized) {
            uint8_t *recv_prbs = payload + RAW_PKT_SEQ_BYTES;

#if IMIX_ENABLED
            // IMIX: PRBS offset hesabı HEP MAX boyut ile yapılır
            // PRBS boyutu paket boyutundan hesaplanır
            uint16_t prbs_len = pkt_len - RAW_PKT_ETH_HDR_SIZE - RAW_PKT_IP_HDR_SIZE -
                                RAW_PKT_UDP_HDR_SIZE - RAW_PKT_SEQ_BYTES;
            if (prbs_len > RAW_MAX_PRBS_BYTES) prbs_len = RAW_MAX_PRBS_BYTES;

            uint64_t prbs_offset = (seq * (uint64_t)RAW_MAX_PRBS_BYTES) % RAW_PRBS_CACHE_SIZE;
            uint8_t *expected_prbs = partner->prbs_cache_ext + prbs_offset;

            if (memcmp(recv_prbs, expected_prbs, prbs_len) == 0) {
                pthread_spin_lock(&source->stats.lock);
                source->stats.good_pkts++;
                pthread_spin_unlock(&source->stats.lock);
            } else {
                pthread_spin_lock(&source->stats.lock);
                source->stats.bad_pkts++;
                for (uint16_t i = 0; i < prbs_len; i++) {
                    source->stats.bit_errors += __builtin_popcount(recv_prbs[i] ^ expected_prbs[i]);
                }
                pthread_spin_unlock(&source->stats.lock);
            }
#else
            uint64_t prbs_offset = (seq * (uint64_t)RAW_PKT_PRBS_BYTES) % RAW_PRBS_CACHE_SIZE;
            uint8_t *expected_prbs = partner->prbs_cache_ext + prbs_offset;

            if (memcmp(recv_prbs, expected_prbs, RAW_PKT_PRBS_BYTES) == 0) {
                pthread_spin_lock(&source->stats.lock);
                source->stats.good_pkts++;
                pthread_spin_unlock(&source->stats.lock);
            } else {
                pthread_spin_lock(&source->stats.lock);
                source->stats.bad_pkts++;
                for (int i = 0; i < RAW_PKT_PRBS_BYTES; i++) {
                    source->stats.bit_errors += __builtin_popcount(recv_prbs[i] ^ expected_prbs[i]);
                }
                pthread_spin_unlock(&source->stats.lock);
            }
#endif
        }

        hdr->tp_status = TP_STATUS_KERNEL;
        port->rx_ring_offset = (port->rx_ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;
    }

    printf("[Port %u RX Worker] Stopped\n", port->port_id);
    port->rx_running = false;
    return NULL;
}

// ==========================================
// MULTI-QUEUE RX WORKER
// ==========================================

// Worker argument structure (passed to each queue worker thread)
struct multi_queue_worker_arg {
    struct raw_socket_port *port;
    struct raw_rx_queue *queue;
};

static struct multi_queue_worker_arg mq_worker_args[MAX_RAW_SOCKET_PORTS][RAW_SOCKET_RX_QUEUE_COUNT];

// Helper function to set CPU affinity
static int set_thread_cpu_affinity(pthread_t thread, int cpu_core)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_core, &cpuset);

    int ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret != 0) {
        fprintf(stderr, "Warning: Failed to set CPU affinity to core %d: %s\n",
                cpu_core, strerror(ret));
        return -1;
    }
    return 0;
}

void *multi_queue_rx_worker(void *arg)
{
    struct multi_queue_worker_arg *warg = (struct multi_queue_worker_arg *)arg;
    struct raw_socket_port *port = warg->port;
    struct raw_rx_queue *queue = warg->queue;

    printf("[Port %u Q%d RX Worker] Started on CPU core %u\n",
           port->port_id, queue->queue_id, queue->cpu_core);

    queue->running = true;

    // Pre-cache PRBS data pointers for DPDK external packet verification
#if DPDK_EXT_TX_ENABLED
    // Port 12 receives from Port 2,3,4,5
    uint8_t *dpdk_prbs_caches_p12[4] = {
        get_prbs_cache_ext_for_port(2),
        get_prbs_cache_ext_for_port(3),
        get_prbs_cache_ext_for_port(4),
        get_prbs_cache_ext_for_port(5)
    };
    // Port 13 receives from Port 0,6
    uint8_t *dpdk_prbs_caches_p13[2] = {
        get_prbs_cache_ext_for_port(0),
        get_prbs_cache_ext_for_port(6)
    };
    // Note: Using global sequence tracking (g_vl_seq) instead of per-queue
#endif

    // Local counters for batch stats update
    uint64_t local_rx_pkts = 0;
    uint64_t local_rx_bytes = 0;
    uint64_t local_good = 0;
    uint64_t local_bad = 0;
    uint64_t local_bit_errors = 0;
    // Note: local_lost removed - using global sequence tracking instead
    const uint32_t STATS_FLUSH_INTERVAL = 1024;
    uint32_t empty_polls = 0;
    const uint32_t BUSY_POLL_COUNT = 64;

    // VL-ID tracking (local, thread-safe)
    uint16_t local_vl_min = 0xFFFF;
    uint16_t local_vl_max = 0;
    uint8_t vl_id_seen[GLOBAL_SEQ_VL_ID_COUNT / 8 + 1];  // Bitmap
    memset(vl_id_seen, 0, sizeof(vl_id_seen));
    queue->vl_id_min = 0xFFFF;
    queue->vl_id_max = 0;
    queue->unique_vl_ids = 0;

    while (!port->stop_flag && (g_stop_flag == NULL || !*g_stop_flag)) {
        struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)(
            (uint8_t *)queue->ring +
            (queue->ring_offset * RAW_SOCKET_RING_FRAME_SIZE));

        if (!(hdr->tp_status & TP_STATUS_USER)) {
            empty_polls++;
            if (empty_polls < BUSY_POLL_COUNT) {
                _mm_pause();
                continue;
            }
            // Flush local stats before blocking
            if (local_rx_pkts > 0) {
                pthread_spin_lock(&port->dpdk_ext_rx_stats.lock);
                port->dpdk_ext_rx_stats.rx_packets += local_rx_pkts;
                port->dpdk_ext_rx_stats.rx_bytes += local_rx_bytes;
                port->dpdk_ext_rx_stats.good_pkts += local_good;
                port->dpdk_ext_rx_stats.bad_pkts += local_bad;
                port->dpdk_ext_rx_stats.bit_errors += local_bit_errors;
                // Note: lost_pkts is calculated globally via get_global_sequence_lost()
                pthread_spin_unlock(&port->dpdk_ext_rx_stats.lock);

                // Also update per-queue stats (no lock needed, thread-local)
                queue->rx_packets += local_rx_pkts;
                queue->rx_bytes += local_rx_bytes;
                queue->good_pkts += local_good;
                queue->bad_pkts += local_bad;
                queue->bit_errors += local_bit_errors;
                // Note: lost_pkts per queue is not used with global tracking

                // Get kernel drop statistics
                struct tpacket_stats kstats;
                socklen_t kstats_len = sizeof(kstats);
                if (getsockopt(queue->socket_fd, SOL_PACKET, PACKET_STATISTICS,
                               &kstats, &kstats_len) == 0) {
                    queue->kernel_drops = kstats.tp_drops;
                }

                // Update VL-ID tracking
                if (local_vl_min < queue->vl_id_min) queue->vl_id_min = local_vl_min;
                if (local_vl_max > queue->vl_id_max) queue->vl_id_max = local_vl_max;

                local_rx_pkts = 0;
                local_rx_bytes = 0;
                local_good = 0;
                local_bad = 0;
                local_bit_errors = 0;
            }
            struct pollfd pfd = {queue->socket_fd, POLLIN, 0};
            poll(&pfd, 1, 1);
            empty_polls = 0;
            continue;
        }
        empty_polls = 0;

        uint8_t *pkt_data = (uint8_t *)hdr + hdr->tp_mac;
        uint32_t pkt_len = hdr->tp_len;

        // Validate minimum packet size
        if (pkt_len < RAW_PKT_ETH_HDR_SIZE + RAW_PKT_IP_HDR_SIZE +
                      RAW_PKT_UDP_HDR_SIZE + RAW_PKT_SEQ_BYTES) {
            hdr->tp_status = TP_STATUS_KERNEL;
            queue->ring_offset = (queue->ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;
            continue;
        }

        // Check EtherType
        uint16_t ethertype = (pkt_data[12] << 8) | pkt_data[13];
        if (ethertype != 0x0800) {
            hdr->tp_status = TP_STATUS_KERNEL;
            queue->ring_offset = (queue->ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;
            continue;
        }

        // Extract VL-ID from DST MAC
        uint16_t vl_id = ((uint16_t)pkt_data[4] << 8) | pkt_data[5];

#if DPDK_EXT_TX_ENABLED
        int dpdk_src_port = dpdk_ext_tx_get_source_port(vl_id);
        if (dpdk_src_port >= 0) {
            uint8_t *payload = pkt_data + 14 + 20 + 8;
            uint64_t seq;
            memcpy(&seq, payload, sizeof(seq));

            local_rx_pkts++;
            local_rx_bytes += pkt_len;

            // VL-ID tracking
            if (vl_id < local_vl_min) local_vl_min = vl_id;
            if (vl_id > local_vl_max) local_vl_max = vl_id;

            // Global sequence tracking (shared across all queues, port-specific)
            struct global_vl_seq_state *vs = NULL;
            uint16_t vl_idx = 0;

            if (port->port_id == 12) {
                vl_idx = vl_id - GLOBAL_SEQ_VL_ID_START_P12;
                if (vl_idx < GLOBAL_SEQ_VL_ID_COUNT_P12) {
                    vs = &g_vl_seq_p12[vl_idx];
                }
            } else if (port->port_id == 13) {
                vl_idx = vl_id - GLOBAL_SEQ_VL_ID_START_P13;
                if (vl_idx < GLOBAL_SEQ_VL_ID_COUNT_P13) {
                    vs = &g_vl_seq_p13[vl_idx];
                }
            }

            if (vs != NULL) {
                // Track unique VL-IDs (per-queue, for debugging)
                uint8_t byte_idx = vl_idx / 8;
                uint8_t bit_mask = 1 << (vl_idx % 8);
                if (!(vl_id_seen[byte_idx] & bit_mask)) {
                    vl_id_seen[byte_idx] |= bit_mask;
                    queue->unique_vl_ids++;
                }

                // Increment RX count
                atomic_fetch_add(&vs->rx_count, 1);

                // Update min_seq (first seen sequence)
                if (!atomic_load(&vs->initialized)) {
                    // First packet for this VL-ID - set min_seq
                    uint64_t expected = UINT64_MAX;
                    if (atomic_compare_exchange_strong(&vs->min_seq, &expected, seq)) {
                        atomic_store(&vs->initialized, true);
                    }
                }

                // Update max_seq if this sequence is higher
                uint64_t old_max = atomic_load(&vs->max_seq);
                while (seq > old_max) {
                    if (atomic_compare_exchange_weak(&vs->max_seq, &old_max, seq)) {
                        break;
                    }
                }

                // Also update min if this is smaller (for late arrivals)
                uint64_t old_min = atomic_load(&vs->min_seq);
                while (seq < old_min) {
                    if (atomic_compare_exchange_weak(&vs->min_seq, &old_min, seq)) {
                        break;
                    }
                }
            }

            // PRBS verification (port-specific cache selection)
            uint8_t *dpdk_prbs_cache = NULL;
            if (port->port_id == 12) {
                // Port 12 receives from Port 2,3,4,5
                int cache_idx = dpdk_src_port - 2;
                if (cache_idx >= 0 && cache_idx < 4) {
                    dpdk_prbs_cache = dpdk_prbs_caches_p12[cache_idx];
                }
            } else if (port->port_id == 13) {
                // Port 13 receives from Port 0,6
                int cache_idx = (dpdk_src_port == 0) ? 0 : ((dpdk_src_port == 6) ? 1 : -1);
                if (cache_idx >= 0 && cache_idx < 2) {
                    dpdk_prbs_cache = dpdk_prbs_caches_p13[cache_idx];
                }
            }
            if (dpdk_prbs_cache) {
                uint8_t *recv_prbs = payload + 8;
                uint16_t cmp_bytes = pkt_len - 14 - 20 - 8 - 8;
                if (cmp_bytes > NUM_PRBS_BYTES) cmp_bytes = NUM_PRBS_BYTES;

                uint64_t prbs_offset = (seq * (uint64_t)NUM_PRBS_BYTES) % PRBS_CACHE_SIZE;
                uint8_t *expected_prbs = dpdk_prbs_cache + prbs_offset;

                if (memcmp(recv_prbs, expected_prbs, cmp_bytes) == 0) {
                    local_good++;
                } else {
                    local_bad++;
                    // Count bit errors
                    for (int b = 0; b < cmp_bytes; b++) {
                        uint8_t diff = recv_prbs[b] ^ expected_prbs[b];
                        local_bit_errors += __builtin_popcount(diff);
                    }
                }
            } else {
                local_good++;  // No cache, assume good
            }

            // Periodic stats flush
            if (local_rx_pkts >= STATS_FLUSH_INTERVAL) {
                pthread_spin_lock(&port->dpdk_ext_rx_stats.lock);
                port->dpdk_ext_rx_stats.rx_packets += local_rx_pkts;
                port->dpdk_ext_rx_stats.rx_bytes += local_rx_bytes;
                port->dpdk_ext_rx_stats.good_pkts += local_good;
                port->dpdk_ext_rx_stats.bad_pkts += local_bad;
                port->dpdk_ext_rx_stats.bit_errors += local_bit_errors;
                pthread_spin_unlock(&port->dpdk_ext_rx_stats.lock);

                queue->rx_packets += local_rx_pkts;
                queue->rx_bytes += local_rx_bytes;
                queue->good_pkts += local_good;
                queue->bad_pkts += local_bad;
                queue->bit_errors += local_bit_errors;

                local_rx_pkts = 0;
                local_rx_bytes = 0;
                local_good = 0;
                local_bad = 0;
                local_bit_errors = 0;
            }

            // Packet handled, continue to next
            hdr->tp_status = TP_STATUS_KERNEL;
            queue->ring_offset = (queue->ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;
            continue;
        }
#endif

        // ==========================================
        // RAW SOCKET SOURCE PACKET HANDLING (from Port 13)
        // ==========================================
        int source_idx = -1;
        for (int s = 0; s < port->rx_source_count; s++) {
            struct raw_rx_source_state *source = &port->rx_sources[s];
            if (vl_id >= source->config.vl_id_start &&
                vl_id < source->config.vl_id_start + source->config.vl_id_count) {
                source_idx = s;
                break;
            }
        }

        if (source_idx >= 0) {
            struct raw_rx_source_state *source = &port->rx_sources[source_idx];
            uint16_t vl_index = vl_id - source->config.vl_id_start;

            // Get sequence number from payload
            uint8_t *payload = pkt_data + RAW_PKT_ETH_HDR_SIZE + RAW_PKT_IP_HDR_SIZE + RAW_PKT_UDP_HDR_SIZE;
            uint64_t seq;
            memcpy(&seq, payload, sizeof(seq));

            pthread_spin_lock(&source->stats.lock);
            source->stats.rx_packets++;
            source->stats.rx_bytes += pkt_len;
            pthread_spin_unlock(&source->stats.lock);

            // Sequence validation
            pthread_spin_lock(&source->vl_sequences[vl_index].rx_lock);

            if (!source->vl_sequences[vl_index].rx_initialized) {
                source->vl_sequences[vl_index].rx_expected_seq = seq + 1;
                source->vl_sequences[vl_index].rx_initialized = true;
            } else {
                uint64_t expected = source->vl_sequences[vl_index].rx_expected_seq;
                if (seq > expected) {
                    uint64_t gap = seq - expected;
                    pthread_spin_lock(&source->stats.lock);
                    source->stats.lost_pkts += gap;
                    pthread_spin_unlock(&source->stats.lock);
                }
                source->vl_sequences[vl_index].rx_expected_seq = seq + 1;
            }

            pthread_spin_unlock(&source->vl_sequences[vl_index].rx_lock);

            // PRBS verification - find partner port
            struct raw_socket_port *partner = NULL;
            uint16_t partner_port_id = source->config.source_port;
            for (int i = 0; i < MAX_RAW_SOCKET_PORTS; i++) {
                if (raw_ports[i].port_id == partner_port_id) {
                    partner = &raw_ports[i];
                    break;
                }
            }

            if (partner && partner->prbs_initialized && partner->prbs_cache_ext) {
                uint8_t *recv_prbs = payload + RAW_PKT_SEQ_BYTES;
#if IMIX_ENABLED
                // IMIX: PRBS offset hesabı HEP MAX boyut ile yapılır
                uint64_t prbs_offset = (seq * (uint64_t)RAW_MAX_PRBS_BYTES) % RAW_PRBS_CACHE_SIZE;
#else
                uint64_t prbs_offset = (seq * (uint64_t)RAW_PKT_PRBS_BYTES) % RAW_PRBS_CACHE_SIZE;
#endif
                uint8_t *expected_prbs = partner->prbs_cache_ext + prbs_offset;

                uint16_t cmp_bytes = pkt_len - RAW_PKT_ETH_HDR_SIZE - RAW_PKT_IP_HDR_SIZE -
                                     RAW_PKT_UDP_HDR_SIZE - RAW_PKT_SEQ_BYTES;
                if (cmp_bytes > RAW_MAX_PRBS_BYTES) cmp_bytes = RAW_MAX_PRBS_BYTES;

                pthread_spin_lock(&source->stats.lock);
                if (memcmp(recv_prbs, expected_prbs, cmp_bytes) == 0) {
                    source->stats.good_pkts++;
                } else {
                    source->stats.bad_pkts++;
                    for (int b = 0; b < cmp_bytes; b++) {
                        uint8_t diff = recv_prbs[b] ^ expected_prbs[b];
                        source->stats.bit_errors += __builtin_popcount(diff);
                    }
                }
                pthread_spin_unlock(&source->stats.lock);
            } else {
                pthread_spin_lock(&source->stats.lock);
                source->stats.good_pkts++;
                pthread_spin_unlock(&source->stats.lock);
            }
        }

        hdr->tp_status = TP_STATUS_KERNEL;
        queue->ring_offset = (queue->ring_offset + 1) % RAW_SOCKET_RING_FRAME_NR;
    }

    // Final stats flush
    if (local_rx_pkts > 0) {
        pthread_spin_lock(&port->dpdk_ext_rx_stats.lock);
        port->dpdk_ext_rx_stats.rx_packets += local_rx_pkts;
        port->dpdk_ext_rx_stats.rx_bytes += local_rx_bytes;
        port->dpdk_ext_rx_stats.good_pkts += local_good;
        port->dpdk_ext_rx_stats.bad_pkts += local_bad;
        port->dpdk_ext_rx_stats.bit_errors += local_bit_errors;
        pthread_spin_unlock(&port->dpdk_ext_rx_stats.lock);

        queue->rx_packets += local_rx_pkts;
        queue->rx_bytes += local_rx_bytes;
        queue->good_pkts += local_good;
        queue->bad_pkts += local_bad;
        queue->bit_errors += local_bit_errors;
    }

    printf("[Port %u Q%d RX Worker] Stopped (pkts=%lu, good=%lu, bad=%lu)\n",
           port->port_id, queue->queue_id, queue->rx_packets,
           queue->good_pkts, queue->bad_pkts);
    queue->running = false;
    return NULL;
}

int start_multi_queue_rx_workers(struct raw_socket_port *port, volatile bool *stop_flag)
{
    if (!port->use_multi_queue_rx) {
        fprintf(stderr, "[Port %u] Multi-queue RX not enabled\n", port->port_id);
        return -1;
    }

    printf("\n=== Starting Multi-Queue RX Workers for Port %u ===\n", port->port_id);

    for (int q = 0; q < port->rx_queue_count; q++) {
        struct raw_rx_queue *queue = &port->rx_queues[q];
        queue->stop_flag = &port->stop_flag;

        // Setup worker argument
        mq_worker_args[port->raw_index][q].port = port;
        mq_worker_args[port->raw_index][q].queue = queue;

        if (pthread_create(&queue->thread, NULL, multi_queue_rx_worker,
                           &mq_worker_args[port->raw_index][q]) != 0) {
            fprintf(stderr, "[Port %u Q%d] Failed to create RX thread: %s\n",
                    port->port_id, q, strerror(errno));
            return -1;
        }

        // Set CPU affinity
        if (queue->cpu_core > 0) {
            if (set_thread_cpu_affinity(queue->thread, queue->cpu_core) == 0) {
                printf("  Queue %d: Thread started, pinned to CPU core %u\n",
                       q, queue->cpu_core);
            }
        } else {
            printf("  Queue %d: Thread started (no CPU pinning)\n", q);
        }
    }

    printf("=== %d Multi-Queue RX Workers Started ===\n", port->rx_queue_count);
    return 0;
}

void stop_multi_queue_rx_workers(struct raw_socket_port *port)
{
    if (!port->use_multi_queue_rx) {
        return;
    }

    printf("\n=== Stopping Multi-Queue RX Workers for Port %u ===\n", port->port_id);

    for (int q = 0; q < port->rx_queue_count; q++) {
        struct raw_rx_queue *queue = &port->rx_queues[q];
        if (queue->running) {
            pthread_join(queue->thread, NULL);
        }
        // Cleanup
        if (queue->ring && queue->ring != MAP_FAILED) {
            munmap(queue->ring, queue->ring_size);
            queue->ring = NULL;
        }
        if (queue->socket_fd >= 0) {
            close(queue->socket_fd);
            queue->socket_fd = -1;
        }
    }

    port->use_multi_queue_rx = false;
    printf("=== Multi-Queue RX Workers Stopped ===\n");
}

// ==========================================
// WORKER MANAGEMENT
// ==========================================

int start_raw_socket_workers(volatile bool *stop_flag)
{
    printf("\n=== Starting Raw Socket Workers (Multi-Target) ===\n");

    g_stop_flag = stop_flag;

    // Start RX workers
    for (int i = 0; i < MAX_RAW_SOCKET_PORTS; i++) {
        raw_ports[i].stop_flag = false;

        // Port 12 (index 0): Use multi-queue RX for high throughput DPDK external packets
        // Port 13 (index 1): Use legacy single-thread RX (lower throughput)
        if (raw_ports[i].use_multi_queue_rx) {
            // Multi-queue RX for Port 12 and Port 13
            if (start_multi_queue_rx_workers(&raw_ports[i], stop_flag) != 0) {
                fprintf(stderr, "[Port %u] Failed to start multi-queue RX workers\n", raw_ports[i].port_id);
                return -1;
            }
        } else {
            // Legacy single-thread RX (fallback)
            if (pthread_create(&raw_ports[i].rx_thread, NULL, raw_rx_worker, &raw_ports[i]) != 0) {
                fprintf(stderr, "[Port %u] Failed to create RX thread\n", raw_ports[i].port_id);
                return -1;
            }
        }
    }

    usleep(100000);  // 100ms

    // Start TX workers
    for (int i = 0; i < MAX_RAW_SOCKET_PORTS; i++) {
        if (pthread_create(&raw_ports[i].tx_thread, NULL, raw_tx_worker, &raw_ports[i]) != 0) {
            fprintf(stderr, "[Port %u] Failed to create TX thread\n", raw_ports[i].port_id);
            return -1;
        }
    }

    printf("=== All Raw Socket Workers Started ===\n");
    return 0;
}

void stop_raw_socket_workers(void)
{
    printf("\n=== Stopping Raw Socket Workers ===\n");

    // Signal all ports to stop
    for (int i = 0; i < MAX_RAW_SOCKET_PORTS; i++) {
        raw_ports[i].stop_flag = true;
    }

    // Wait for all workers to finish
    for (int i = 0; i < MAX_RAW_SOCKET_PORTS; i++) {
        // Stop TX thread
        if (raw_ports[i].tx_running) {
            pthread_join(raw_ports[i].tx_thread, NULL);
        }

        // Stop RX - multi-queue or legacy
        if (raw_ports[i].use_multi_queue_rx) {
            stop_multi_queue_rx_workers(&raw_ports[i]);
        } else {
            if (raw_ports[i].rx_running) {
                pthread_join(raw_ports[i].rx_thread, NULL);
            }
        }
    }

    printf("=== All Raw Socket Workers Stopped ===\n");
}

// ==========================================
// STATISTICS
// ==========================================

static uint64_t prev_tx_bytes[MAX_RAW_SOCKET_PORTS][MAX_RAW_TARGETS] = {{0}};
static uint64_t prev_rx_bytes[MAX_RAW_SOCKET_PORTS][MAX_RAW_TARGETS] = {{0}};
static uint64_t prev_dpdk_ext_rx_bytes_p12 = 0;  // Port 12 DPDK RX tracking
static uint64_t prev_dpdk_ext_rx_bytes_p13 = 0;  // Port 13 DPDK RX tracking
static uint64_t last_stats_time_ns = 0;

void print_raw_socket_stats(void)
{
    uint64_t now_ns = get_time_ns();
    double elapsed_sec = 1.0;

    if (last_stats_time_ns > 0) {
        elapsed_sec = (double)(now_ns - last_stats_time_ns) / 1000000000.0;
        if (elapsed_sec < 0.1) elapsed_sec = 1.0;
    }
    last_stats_time_ns = now_ns;

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                           Raw Socket Multi-Target Statistics                                                                                                               ║\n");
    printf("╠══════════════╦══════════════╦════════════════╦═════════════════════╦════════════════╦═════════════════════╦═════════════════════╦═════════════════════╦═════════════════════╦═════════════════════╦═════════════════════════╣\n");
    printf("║    Source    ║    Target    ║      Rate      ║       TX Pkts       ║    TX Mbps     ║       RX Pkts       ║        Good         ║         Bad         ║        Lost         ║     Bit Errors      ║           BER           ║\n");
    printf("╠══════════════╬══════════════╬════════════════╬═════════════════════╬════════════════╬═════════════════════╬═════════════════════╬═════════════════════╬═════════════════════╬═════════════════════╬═════════════════════════╣\n");

    for (int p = 0; p < MAX_RAW_SOCKET_PORTS; p++) {
        struct raw_socket_port *port = &raw_ports[p];

        // Print TX targets
        for (int t = 0; t < port->tx_target_count; t++) {
            struct raw_tx_target_state *target = &port->tx_targets[t];

            pthread_spin_lock(&target->stats.lock);

            uint64_t tx_bytes_delta = target->stats.tx_bytes - prev_tx_bytes[p][t];
            double tx_mbps = (tx_bytes_delta * 8.0) / (elapsed_sec * 1000000.0);
            prev_tx_bytes[p][t] = target->stats.tx_bytes;

            // Find corresponding RX stats from the destination port
            uint64_t rx_pkts = 0, good = 0, bad = 0, lost = 0, bit_err = 0;

            // Look for RX source in the destination port
            for (int dp = 0; dp < MAX_RAW_SOCKET_PORTS; dp++) {
                if (raw_ports[dp].port_id == target->config.dest_port) {
                    for (int s = 0; s < raw_ports[dp].rx_source_count; s++) {
                        if (raw_ports[dp].rx_sources[s].config.source_port == port->port_id &&
                            raw_ports[dp].rx_sources[s].config.vl_id_start == target->config.vl_id_start) {
                            struct raw_rx_source_state *src = &raw_ports[dp].rx_sources[s];
                            pthread_spin_lock(&src->stats.lock);
                            rx_pkts = src->stats.rx_packets;
                            good = src->stats.good_pkts;
                            bad = src->stats.bad_pkts;
                            lost = src->stats.lost_pkts;
                            bit_err = src->stats.bit_errors;
                            pthread_spin_unlock(&src->stats.lock);
                            break;
                        }
                    }
                    break;
                }
            }

            // Calculate BER for this target
            double target_ber = 0.0;
            if (rx_pkts > 0) {
                uint64_t rx_bytes_est = rx_pkts * 1509;  // Estimated bytes
                target_ber = (double)bit_err / (rx_bytes_est * 8.0);
            }

            printf("║     P%-3u     ║     P%-3u     ║    %3u Mbps    ║ %19lu ║ %14.2f ║ %19lu ║ %19lu ║ %19lu ║ %19lu ║ %19lu ║ %23.2e ║\n",
                   port->port_id, target->config.dest_port, target->config.rate_mbps,
                   target->stats.tx_packets, tx_mbps,
                   rx_pkts, good, bad, lost, bit_err, target_ber);

            pthread_spin_unlock(&target->stats.lock);
        }
    }

    printf("╚══════════════╩══════════════╩════════════════╩═════════════════════╩════════════════╩═════════════════════╩═════════════════════╩═════════════════════╩═════════════════════╩═════════════════════╩═════════════════════════╝\n");

    // Show DPDK External RX stats for Port 12
#if DPDK_EXT_TX_ENABLED
    struct raw_socket_port *port12 = &raw_ports[0]; // Port 12 is index 0
    if (port12->port_id == 12) {
        pthread_spin_lock(&port12->dpdk_ext_rx_stats.lock);
        uint64_t dpdk_rx = port12->dpdk_ext_rx_stats.rx_packets;
        uint64_t dpdk_rx_bytes = port12->dpdk_ext_rx_stats.rx_bytes;
        uint64_t dpdk_good = port12->dpdk_ext_rx_stats.good_pkts;
        uint64_t dpdk_bad = port12->dpdk_ext_rx_stats.bad_pkts;
        uint64_t dpdk_bit_err = port12->dpdk_ext_rx_stats.bit_errors;
        pthread_spin_unlock(&port12->dpdk_ext_rx_stats.lock);

        // Get lost count from global sequence tracking
        uint64_t dpdk_lost = get_global_sequence_lost();

        // Calculate RX rate in Mbps
        uint64_t rx_bytes_delta = dpdk_rx_bytes - prev_dpdk_ext_rx_bytes_p12;
        double rx_mbps = (rx_bytes_delta * 8.0) / (elapsed_sec * 1000000.0);
        prev_dpdk_ext_rx_bytes_p12 = dpdk_rx_bytes;

        // Calculate BER (Bit Error Rate) - bit_errors / total_bits_received
        double ber = 0.0;
        if (dpdk_rx_bytes > 0) {
            ber = (double)dpdk_bit_err / (dpdk_rx_bytes * 8.0);
        }

        printf("\n┌══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════┐\n");
        printf("│  Port 12 RX: DPDK External TX Packets (from Port 2,3,4,5)                                                                                                                                                              │\n");
        printf("├═════════════════════════════════════╦══════════════════════════╦═════════════════════════════════════╦═════════════════════════════════════╦═════════════════════════════════════╦═════════════════════════════════════╦═════════════════════════╣\n");
        printf("│              RX Pkts                ║         RX Mbps          ║               Good                  ║               Bad                   ║            Bit Errors               ║               Lost                  ║           BER           ║\n");
        printf("├═════════════════════════════════════╬══════════════════════════╬═════════════════════════════════════╬═════════════════════════════════════╬═════════════════════════════════════╬═════════════════════════════════════╬═════════════════════════╣\n");
        printf("│ %35lu ║ %24.2f ║ %35lu ║ %35lu ║ %35lu ║ %35lu ║ %23.2e ║\n",
               dpdk_rx, rx_mbps, dpdk_good, dpdk_bad, dpdk_bit_err, dpdk_lost, ber);
        printf("└═════════════════════════════════════╩══════════════════════════╩═════════════════════════════════════╩═════════════════════════════════════╩═════════════════════════════════════╩═════════════════════════════════════╩═════════════════════════┘\n");

        // Show per-queue statistics if multi-queue is enabled
        if (port12->use_multi_queue_rx && port12->rx_queue_count > 0) {
            printf("  Multi-Queue RX Stats (Lost is tracked globally across all queues):\n");
            for (int q = 0; q < port12->rx_queue_count; q++) {
                struct raw_rx_queue *rq = &port12->rx_queues[q];
                printf("    Q%d (CPU %2u): RX=%9lu Good=%9lu KDrop=%8lu VL-ID=[%u-%u] (%u unique)\n",
                       q, rq->cpu_core, rq->rx_packets, rq->good_pkts, rq->kernel_drops,
                       rq->vl_id_min == 0xFFFF ? 0 : rq->vl_id_min,
                       rq->vl_id_max,
                       rq->unique_vl_ids);
            }
            // Debug: show per-VL-ID sequence stats
            print_global_sequence_debug();
        }
    }

    // Port 13 DPDK External RX Stats (from Port 0,6)
    struct raw_socket_port *port13 = &raw_ports[1]; // Port 13 is index 1
    if (port13->port_id == 13) {
        pthread_spin_lock(&port13->dpdk_ext_rx_stats.lock);
        uint64_t dpdk_rx_p13 = port13->dpdk_ext_rx_stats.rx_packets;
        uint64_t dpdk_rx_bytes_p13 = port13->dpdk_ext_rx_stats.rx_bytes;
        uint64_t dpdk_good_p13 = port13->dpdk_ext_rx_stats.good_pkts;
        uint64_t dpdk_bad_p13 = port13->dpdk_ext_rx_stats.bad_pkts;
        uint64_t dpdk_bit_err_p13 = port13->dpdk_ext_rx_stats.bit_errors;
        pthread_spin_unlock(&port13->dpdk_ext_rx_stats.lock);
        // Get lost from global sequence tracking (not from stats struct)
        uint64_t dpdk_lost_p13 = get_global_sequence_lost_p13();

        // Calculate RX rate in Mbps for Port 13
        uint64_t rx_bytes_delta_p13 = dpdk_rx_bytes_p13 - prev_dpdk_ext_rx_bytes_p13;
        double rx_mbps_p13 = (rx_bytes_delta_p13 * 8.0) / (elapsed_sec * 1000000.0);
        prev_dpdk_ext_rx_bytes_p13 = dpdk_rx_bytes_p13;

        // Calculate BER for Port 13
        double ber_p13 = 0.0;
        if (dpdk_rx_bytes_p13 > 0) {
            ber_p13 = (double)dpdk_bit_err_p13 / (dpdk_rx_bytes_p13 * 8.0);
        }

        printf("\n┌══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════┐\n");
        printf("│  Port 13 RX: DPDK External TX Packets (from Port 0,6)                                                                                                                                                                  │\n");
        printf("├═════════════════════════════════════╦══════════════════════════╦═════════════════════════════════════╦═════════════════════════════════════╦═════════════════════════════════════╦═════════════════════════════════════╦═════════════════════════╣\n");
        printf("│              RX Pkts                ║         RX Mbps          ║               Good                  ║               Bad                   ║            Bit Errors               ║               Lost                  ║           BER           ║\n");
        printf("├═════════════════════════════════════╬══════════════════════════╬═════════════════════════════════════╬═════════════════════════════════════╬═════════════════════════════════════╬═════════════════════════════════════╬═════════════════════════╣\n");
        printf("│ %35lu ║ %24.2f ║ %35lu ║ %35lu ║ %35lu ║ %35lu ║ %23.2e ║\n",
               dpdk_rx_p13, rx_mbps_p13, dpdk_good_p13, dpdk_bad_p13, dpdk_bit_err_p13, dpdk_lost_p13, ber_p13);
        printf("└═════════════════════════════════════╩══════════════════════════╩═════════════════════════════════════╩═════════════════════════════════════╩═════════════════════════════════════╩═════════════════════════════════════╩═════════════════════════┘\n");

        // Show per-queue statistics if multi-queue is enabled for Port 13
        if (port13->use_multi_queue_rx && port13->rx_queue_count > 0) {
            printf("  Multi-Queue RX Stats:\n");
            for (int q = 0; q < port13->rx_queue_count; q++) {
                struct raw_rx_queue *rq = &port13->rx_queues[q];
                printf("    Q%d (CPU %2u): RX=%9lu Good=%9lu KDrop=%8lu VL-ID=[%u-%u] (%u unique)\n",
                       q, rq->cpu_core, rq->rx_packets, rq->good_pkts, rq->kernel_drops,
                       rq->vl_id_min == 0xFFFF ? 0 : rq->vl_id_min,
                       rq->vl_id_max,
                       rq->unique_vl_ids);
            }
        }
    }
#endif
}

void reset_raw_socket_stats(void)
{
    for (int p = 0; p < MAX_RAW_SOCKET_PORTS; p++) {
        struct raw_socket_port *port = &raw_ports[p];

        for (int t = 0; t < port->tx_target_count; t++) {
            pthread_spin_lock(&port->tx_targets[t].stats.lock);
            memset(&port->tx_targets[t].stats, 0, sizeof(struct raw_target_stats));
            pthread_spin_init(&port->tx_targets[t].stats.lock, PTHREAD_PROCESS_PRIVATE);
            pthread_spin_unlock(&port->tx_targets[t].stats.lock);
            prev_tx_bytes[p][t] = 0;
        }

        for (int s = 0; s < port->rx_source_count; s++) {
            pthread_spin_lock(&port->rx_sources[s].stats.lock);
            memset(&port->rx_sources[s].stats, 0, sizeof(struct raw_target_stats));
            pthread_spin_init(&port->rx_sources[s].stats.lock, PTHREAD_PROCESS_PRIVATE);
            pthread_spin_unlock(&port->rx_sources[s].stats.lock);
            prev_rx_bytes[p][s] = 0;
        }

        // Reset DPDK external RX stats
        pthread_spin_lock(&port->dpdk_ext_rx_stats.lock);
        memset(&port->dpdk_ext_rx_stats, 0, sizeof(struct raw_target_stats));
        pthread_spin_init(&port->dpdk_ext_rx_stats.lock, PTHREAD_PROCESS_PRIVATE);
        pthread_spin_unlock(&port->dpdk_ext_rx_stats.lock);
    }
    prev_dpdk_ext_rx_bytes_p12 = 0;
    prev_dpdk_ext_rx_bytes_p13 = 0;
    last_stats_time_ns = 0;

    // Reset global sequence tracking
    reset_global_sequence_tracking();
    printf("Raw socket statistics reset\n");
}

// ==========================================
// CLEANUP
// ==========================================

void cleanup_raw_socket_ports(void)
{
    printf("\n=== Cleaning up Raw Socket Ports ===\n");

    for (int i = 0; i < MAX_RAW_SOCKET_PORTS; i++) {
        struct raw_socket_port *port = &raw_ports[i];

        port->stop_flag = true;

        if (port->tx_ring && port->tx_ring != MAP_FAILED) {
            munmap(port->tx_ring, port->tx_ring_size);
        }
        if (port->tx_socket >= 0) close(port->tx_socket);

        // Cleanup RX - multi-queue or legacy
        if (port->use_multi_queue_rx) {
            // Multi-queue cleanup (rings and sockets already closed by stop_multi_queue_rx_workers)
            for (int q = 0; q < port->rx_queue_count; q++) {
                struct raw_rx_queue *queue = &port->rx_queues[q];
                if (queue->ring && queue->ring != MAP_FAILED) {
                    munmap(queue->ring, queue->ring_size);
                    queue->ring = NULL;
                }
                if (queue->socket_fd >= 0) {
                    close(queue->socket_fd);
                    queue->socket_fd = -1;
                }
            }
        } else {
            // Legacy single-queue cleanup
            if (port->rx_ring && port->rx_ring != MAP_FAILED) {
                munmap(port->rx_ring, port->rx_ring_size);
            }
            if (port->rx_socket >= 0) close(port->rx_socket);
        }

        if (port->prbs_cache) free(port->prbs_cache);
        if (port->prbs_cache_ext) free(port->prbs_cache_ext);

        for (int t = 0; t < port->tx_target_count; t++) {
            if (port->tx_targets[t].vl_sequences) {
                for (uint16_t v = 0; v < port->tx_targets[t].config.vl_id_count; v++) {
                    pthread_spin_destroy(&port->tx_targets[t].vl_sequences[v].tx_lock);
                    pthread_spin_destroy(&port->tx_targets[t].vl_sequences[v].rx_lock);
                }
                free(port->tx_targets[t].vl_sequences);
            }
            pthread_spin_destroy(&port->tx_targets[t].stats.lock);
        }

        for (int s = 0; s < port->rx_source_count; s++) {
            if (port->rx_sources[s].vl_sequences) {
                for (uint16_t v = 0; v < port->rx_sources[s].config.vl_id_count; v++) {
                    pthread_spin_destroy(&port->rx_sources[s].vl_sequences[v].tx_lock);
                    pthread_spin_destroy(&port->rx_sources[s].vl_sequences[v].rx_lock);
                }
                free(port->rx_sources[s].vl_sequences);
            }
            pthread_spin_destroy(&port->rx_sources[s].stats.lock);
        }

        // Cleanup DPDK external RX stats
        pthread_spin_destroy(&port->dpdk_ext_rx_stats.lock);

        printf("[Raw Port %d] Cleanup complete\n", port->port_id);
    }

    printf("=== Raw Socket Ports Cleanup Complete ===\n");
}
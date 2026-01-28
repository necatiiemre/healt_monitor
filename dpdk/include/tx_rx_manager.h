#ifndef TX_RX_MANAGER_H
#define TX_RX_MANAGER_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_atomic.h>
#include "port.h"
#include "packet.h"
#include "config.h"

#define TX_RING_SIZE 2048
#define RX_RING_SIZE 8192
#define NUM_MBUFS 524287
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 32

// VL-ID range limits
// Her port'un tx_vl_ids başlangıç değerleri farklı olabilir (örn: Port 7 → 3971)
// Her queue için 128 VL-ID aralığı var
// Raw socket portları için genişletildi:
//   - Raw Port 0 (1G): 4099-4226 (128 VL-ID)
//   - Raw Port 1 (100M): 4227-4258 (32 VL-ID)
// DPDK External TX için genişletildi:
//   - Port 2: 4259-4386, Port 3: 4387-4514
//   - Port 0: 4515-4642, Port 1: 4643-4770
#define MAX_VL_ID 4800  // Increased to support DPDK external TX (up to 4770)
#define MIN_VL_ID 3
#define VL_RANGE_SIZE_PER_QUEUE 128  // Her queue için 128 VL-ID

// Global VLAN configuration for all ports
extern struct port_vlan_config port_vlans[MAX_PORTS_CONFIG];

/**
 * Token bucket for rate limiting
 */
struct rate_limiter
{
    uint64_t tokens;         // Current tokens (in bytes)
    uint64_t max_tokens;     // Maximum tokens (bucket size)
    uint64_t tokens_per_sec; // Token generation rate (bytes/sec)
    uint64_t last_update;    // Last update timestamp (TSC cycles)
    uint64_t tsc_hz;         // TSC frequency
};

// RX Statistics per port
struct rx_stats
{
    rte_atomic64_t total_rx_pkts;
    rte_atomic64_t good_pkts;
    rte_atomic64_t bad_pkts;
    rte_atomic64_t bit_errors;
    rte_atomic64_t out_of_order_pkts;  // Sıra dışı gelen paketler
    rte_atomic64_t lost_pkts;          // Kayıp paketler (sequence gap)
    rte_atomic64_t duplicate_pkts;     // Tekrar eden paketler
    rte_atomic64_t short_pkts;         // Minimum uzunluktan kısa paketler
    rte_atomic64_t external_pkts;      // Harici hatlardan gelen paketler (VL-ID aralık dışı)
    // Raw socket paketleri (non-VLAN) - DPDK'dan ayrı takip
    rte_atomic64_t raw_socket_rx_pkts; // Raw socket'ten gelen paket sayısı
    rte_atomic64_t raw_socket_rx_bytes; // Raw socket'ten gelen byte sayısı
};

extern struct rx_stats rx_stats_per_port[MAX_PORTS];

/**
 * VL-ID based sequence tracking (lock-free, watermark-based)
 * Uses highest-seen watermark instead of expected sequence
 * This approach handles RSS-induced reordering correctly
 */
struct vl_sequence_tracker {
    volatile uint64_t max_seq;       // Highest sequence seen for this VL-ID
    volatile uint64_t pkt_count;     // Total packets received for this VL-ID
    volatile uint64_t expected_seq;  // Expected next sequence for real-time gap detection
    volatile int initialized;        // Has this VL-ID been seen before? (0=false, 1=true)
};

/**
 * Per-port VL-ID sequence tracking table
 * Lock-free design: each VL-ID tracker uses atomic operations
 */
struct port_vl_tracker {
    struct vl_sequence_tracker vl_trackers[MAX_VL_ID + 1];  // Index by VL-ID
    // No lock needed - using lock-free atomic operations per VL-ID
};

extern struct port_vl_tracker port_vl_trackers[MAX_PORTS];

/**
 * TX/RX configuration for a port
 */
struct txrx_config
{
    uint16_t port_id;
    uint16_t nb_tx_queues;
    uint16_t nb_rx_queues;
    struct rte_mempool *mbuf_pool;
};

/**
 * TX worker parameters
 */
struct tx_worker_params
{
    uint16_t port_id;
    uint16_t dst_port_id;
    uint16_t queue_id;
    uint16_t lcore_id;
    uint16_t vlan_id;       // VLAN header tag (802.1Q)
    uint16_t vl_id;         // VL ID for MAC/IP (different from VLAN)
    struct packet_config pkt_config;
    struct rte_mempool *mbuf_pool;
    volatile bool *stop_flag;
    uint64_t sequence_number;  // Not used anymore - VL-ID based now
    struct rate_limiter limiter;

    // External TX parameters (for Port 12 via switch)
    bool ext_tx_enabled;        // Is external TX enabled for this worker?
    uint16_t ext_vlan_id;       // External TX VLAN tag
    uint16_t ext_vl_id_start;   // External TX VL-ID start
    uint16_t ext_vl_id_count;   // External TX VL-ID count
    struct rate_limiter ext_limiter;  // Separate rate limiter for external TX
};

/**
 * RX worker parameters
 */
struct rx_worker_params
{
    uint16_t port_id;
    uint16_t src_port_id;
    uint16_t queue_id;
    uint16_t lcore_id;
    uint16_t vlan_id;       // VLAN header tag (802.1Q)
    uint16_t vl_id;         // VL ID for MAC/IP (different from VLAN)
    volatile bool *stop_flag;
};

/**
 * Initialize VLAN configuration from config.h
 */
void init_vlan_config(void);

/**
 * Get TX VLAN ID for a specific port and queue
 */
uint16_t get_tx_vlan_for_queue(uint16_t port_id, uint16_t queue_id);

/**
 * Get RX VLAN ID for a specific port and queue
 */
uint16_t get_rx_vlan_for_queue(uint16_t port_id, uint16_t queue_id);

/**
 * Get TX VL ID for a specific port and queue
 */
uint16_t get_tx_vl_id_for_queue(uint16_t port_id, uint16_t queue_id);

/**
 * Get RX VL ID for a specific port and queue
 */
uint16_t get_rx_vl_id_for_queue(uint16_t port_id, uint16_t queue_id);

/**
 * Print VLAN configuration for all ports
 */
void print_vlan_config(void);

/**
 * Initialize TX/RX for a port
 */
int init_port_txrx(uint16_t port_id, struct txrx_config *config);

/**
 * Create mbuf pool for a socket
 */
struct rte_mempool *create_mbuf_pool(uint16_t socket_id, uint16_t port_id);

/**
 * Setup TX queue
 */
int setup_tx_queue(uint16_t port_id, uint16_t queue_id, uint16_t socket_id);

/**
 * Setup RX queue
 */
int setup_rx_queue(uint16_t port_id, uint16_t queue_id, uint16_t socket_id,
                   struct rte_mempool *mbuf_pool);

/**
 * TX worker thread function with VL-ID based sequencing
 */
int tx_worker(void *arg);

/**
 * RX worker thread function with PRBS verification and VL-ID based sequence validation
 */
int rx_worker(void *arg);

/**
 * Start TX/RX workers for all ports
 */
int start_txrx_workers(struct ports_config *ports_config, volatile bool *stop_flag);

/**
 * Print port statistics from DPDK
 */
void print_port_stats(struct ports_config *ports_config);

/**
 * Initialize RX statistics and VL-ID trackers
 */
void init_rx_stats(void);

// ==========================================
// LATENCY TEST STRUCTURES & FUNCTIONS
// ==========================================

#if LATENCY_TEST_ENABLED

// Tek bir latency ölçüm sonucu (çoklu örnek destekli)
struct latency_result {
    uint16_t tx_port;           // Gönderen port
    uint16_t rx_port;           // Alan port
    uint16_t vlan_id;           // VLAN ID
    uint16_t vl_id;             // VL-ID
    uint64_t tx_timestamp;      // Son TX zamanı (TSC cycles)
    uint64_t rx_timestamp;      // Son RX zamanı (TSC cycles)
    uint64_t latency_cycles;    // Son gecikme (cycles)
    double   latency_us;        // Ortalama gecikme (mikrosaniye)
    double   min_latency_us;    // Minimum gecikme
    double   max_latency_us;    // Maximum gecikme
    double   sum_latency_us;    // Toplam gecikme (ortalama hesabı için)
    uint32_t tx_count;          // Gönderilen paket sayısı
    uint32_t rx_count;          // Alınan paket sayısı
    bool     received;          // En az 1 paket alındı mı?
    bool     prbs_ok;           // PRBS doğrulama başarılı mı?
};

// Port başına latency test durumu
#define MAX_LATENCY_TESTS_PER_PORT 32  // Max VLAN sayısı kadar

struct port_latency_test {
    uint16_t port_id;
    uint16_t test_count;                                    // Bu port için test sayısı
    struct latency_result results[MAX_LATENCY_TESTS_PER_PORT];
    volatile bool tx_complete;                              // TX tamamlandı mı?
    volatile bool rx_complete;                              // Tüm RX tamamlandı mı?
};

// Global latency test durumu
struct latency_test_state {
    volatile bool test_running;             // Test devam ediyor mu?
    volatile bool test_complete;            // Test tamamlandı mı?
    uint64_t tsc_hz;                        // TSC frekansı (cycles/sec)
    uint64_t test_start_time;               // Test başlangıç zamanı
    struct port_latency_test ports[MAX_PORTS];
};

extern struct latency_test_state g_latency_test;

/**
 * Latency testi başlat
 * Her port için her VLAN'dan 1 paket gönderir
 */
int start_latency_test(struct ports_config *ports_config, volatile bool *stop_flag);

/**
 * Latency test sonuçlarını yazdır
 */
void print_latency_results(void);

/**
 * Latency test durumunu sıfırla
 */
void reset_latency_test(void);

#endif /* LATENCY_TEST_ENABLED */

#endif /* TX_RX_MANAGER_H */
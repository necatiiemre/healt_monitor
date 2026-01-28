#ifndef DPDK_EXTERNAL_TX_H
#define DPDK_EXTERNAL_TX_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_atomic.h>
#include "config.h"
#include "port.h"

// ==========================================
// DPDK EXTERNAL TX SYSTEM
// ==========================================
// Mevcut DPDK TX'ten BAĞIMSIZ çalışan harici TX sistemi.
// Port 2,3,4,5'ten switch üzerinden Port 12'ye paket gönderir.
// Port 12 (raw socket) bu paketleri alıp doğrulama yapar.

#if DPDK_EXT_TX_ENABLED

// External TX worker parameters
struct dpdk_ext_tx_worker_params {
    uint16_t port_id;           // DPDK port ID (2-5)
    uint16_t queue_id;          // TX queue ID (0-3)
    uint16_t lcore_id;          // Assigned lcore
    uint16_t vlan_id;           // VLAN tag
    uint16_t vl_id_start;       // VL-ID başlangıç
    uint16_t vl_id_count;       // VL-ID sayısı
    uint32_t rate_mbps;         // Hedef hız
    struct rte_mempool *mbuf_pool;
    volatile bool *stop_flag;
};

// Per-port external TX statistics
struct dpdk_ext_tx_stats {
    rte_atomic64_t tx_pkts;     // Gönderilen paket sayısı
    rte_atomic64_t tx_bytes;    // Gönderilen byte sayısı
};

// Global external TX statistics
extern struct dpdk_ext_tx_stats dpdk_ext_tx_stats_per_port[DPDK_EXT_TX_PORT_COUNT];

// External TX port runtime structure
struct dpdk_ext_tx_port {
    uint16_t port_id;
    bool initialized;
    struct dpdk_ext_tx_port_config config;
    struct rte_mempool *mbuf_pool;

    // PRBS cache (shared with main system or separate)
    uint8_t *prbs_cache_ext;
    size_t prbs_cache_size;
    bool prbs_initialized;

    // Per-VL-ID sequence numbers
    uint64_t *vl_sequences;  // [MAX_VL_ID + 1]
};

// Global external TX ports array
extern struct dpdk_ext_tx_port dpdk_ext_tx_ports[DPDK_EXT_TX_PORT_COUNT];

/**
 * Initialize the DPDK external TX system
 * @param mbuf_pools Array of mbuf pools for each port
 * @return 0 on success, negative on error
 */
int dpdk_ext_tx_init(struct rte_mempool *mbuf_pools[]);

/**
 * Start all external TX workers
 * @param ports_config Pointer to ports configuration (for lcore assignment)
 * @param stop_flag Pointer to stop flag
 * @return 0 on success, negative on error
 */
int dpdk_ext_tx_start_workers(struct ports_config *ports_config, volatile bool *stop_flag);

/**
 * External TX worker function (runs on lcore)
 * @param arg Pointer to dpdk_ext_tx_worker_params
 * @return 0 on success
 */
int dpdk_ext_tx_worker(void *arg);

/**
 * Get external TX statistics for a port
 * @param port_id DPDK port ID
 * @param tx_pkts Output: packet count
 * @param tx_bytes Output: byte count
 */
void dpdk_ext_tx_get_stats(uint16_t port_id, uint64_t *tx_pkts, uint64_t *tx_bytes);

/**
 * Print external TX statistics
 */
void dpdk_ext_tx_print_stats(void);

/**
 * Check if a VL-ID belongs to external TX range
 * @param vl_id VL-ID to check
 * @return Source port ID if external, -1 if not
 */
int dpdk_ext_tx_get_source_port(uint16_t vl_id);

#endif /* DPDK_EXT_TX_ENABLED */

#endif /* DPDK_EXTERNAL_TX_H */

#ifndef HEALTH_MONITOR_H
#define HEALTH_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "health_types.h"

// ==========================================
// HEALTH MONITOR CONFIGURATION
// ==========================================

#define HEALTH_MONITOR_INTERFACE "eno12409"  // Port 13 interface
#define HEALTH_MONITOR_QUERY_INTERVAL_MS 1000  // Query interval (1 second)
#define HEALTH_MONITOR_RESPONSE_TIMEOUT_MS 500  // Response timeout (500ms)
#define HEALTH_MONITOR_EXPECTED_RESPONSES 6  // Expected response count
#define HEALTH_MONITOR_QUERY_SIZE 64  // Query packet size
#define HEALTH_MONITOR_SEQ_INIT 0x2F  // Initial sequence number (47)
#define HEALTH_MONITOR_RX_BUFFER_SIZE 2048  // RX buffer size

// VL_IDX for response filtering (DST MAC offset 4-5)
#define HEALTH_MONITOR_RESPONSE_VL_IDX 0x1184  // 4484 decimal
#define HEALTH_MONITOR_RESPONSE_VL_IDX_HIGH 0x11
#define HEALTH_MONITOR_RESPONSE_VL_IDX_LOW 0x84

// ==========================================
// HEALTH MONITOR STATISTICS
// ==========================================

struct health_monitor_stats {
    uint64_t queries_sent;        // Total queries sent
    uint64_t responses_received;  // Total responses received
    uint64_t timeouts;            // Cycles with incomplete responses
    uint8_t  current_sequence;    // Current sequence number
    uint64_t last_cycle_time_ms;  // Last cycle duration in ms
    uint8_t  last_response_count; // Responses in last cycle
};

// ==========================================
// HEALTH MONITOR STATE
// ==========================================

struct health_monitor_state {
    // Thread
    pthread_t thread;
    volatile bool running;

    // Sockets
    int tx_socket;
    int rx_socket;
    int if_index;

    // Query packet (template)
    uint8_t query_packet[HEALTH_MONITOR_QUERY_SIZE];

    // Sequence tracking
    uint8_t sequence;

    // Statistics
    struct health_monitor_stats stats;
    pthread_spinlock_t stats_lock;
};

// ==========================================
// FUNCTION DECLARATIONS
// ==========================================

/**
 * @brief Initialize health monitor system
 * @return 0 on success, -1 on failure
 */
int init_health_monitor(void);

/**
 * @brief Start health monitor thread
 * @param stop_flag Pointer to global stop flag
 * @return 0 on success, -1 on failure
 */
int start_health_monitor(volatile bool *stop_flag);

/**
 * @brief Stop health monitor thread
 */
void stop_health_monitor(void);

/**
 * @brief Cleanup health monitor resources
 */
void cleanup_health_monitor(void);

/**
 * @brief Get health monitor statistics (thread-safe copy)
 * @param stats Output statistics structure
 */
void get_health_monitor_stats(struct health_monitor_stats *stats);

/**
 * @brief Print health monitor statistics
 */
void print_health_monitor_stats(void);

/**
 * @brief Check if health monitor is running
 * @return true if running
 */
bool is_health_monitor_running(void);

#endif // HEALTH_MONITOR_H

/**
 * @file common.h
 * @brief HW Timestamp Latency Test - Common definitions and debug macros
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

#include "config.h"

// ============================================
// COLOR CODES FOR TERMINAL OUTPUT
// Disabled for clean log files - enable if needed for terminal
// ============================================
#define COLOR_RESET     ""
#define COLOR_RED       ""
#define COLOR_GREEN     ""
#define COLOR_YELLOW    ""
#define COLOR_BLUE      ""
#define COLOR_MAGENTA   ""
#define COLOR_CYAN      ""
#define COLOR_BOLD      ""

// ============================================
// GLOBAL DEBUG LEVEL (set from command line)
// ============================================
extern int g_debug_level;

// ============================================
// DEBUG MACROS
// ============================================

// Timestamp prefix for debug messages
#define DEBUG_TIMESTAMP() do { \
    struct timespec _ts; \
    clock_gettime(CLOCK_MONOTONIC, &_ts); \
    printf("[%5ld.%06ld] ", _ts.tv_sec % 100000, _ts.tv_nsec / 1000); \
} while(0)

// ERROR: Always printed
#define LOG_ERROR(fmt, ...) do { \
    fflush(stdout); \
    DEBUG_TIMESTAMP(); \
    printf("[ERROR] " fmt "\n", ##__VA_ARGS__); \
    fflush(stdout); \
} while(0)

// ERROR with errno
#define LOG_ERROR_ERRNO(fmt, ...) do { \
    int _errno = errno; \
    fflush(stdout); \
    DEBUG_TIMESTAMP(); \
    printf("[ERROR] " fmt ": %s (errno=%d)\n", \
            ##__VA_ARGS__, strerror(_errno), _errno); \
    fflush(stdout); \
} while(0)

// WARNING: Always printed
#define LOG_WARN(fmt, ...) do { \
    fflush(stdout); \
    DEBUG_TIMESTAMP(); \
    printf("[WARN]  " fmt "\n", ##__VA_ARGS__); \
    fflush(stdout); \
} while(0)

// INFO: Printed when debug_level >= 1
#define LOG_INFO(fmt, ...) do { \
    if (g_debug_level >= DEBUG_LEVEL_INFO) { \
        fflush(stdout); \
        DEBUG_TIMESTAMP(); \
        printf("[INFO]  " fmt "\n", ##__VA_ARGS__); \
        fflush(stdout); \
    } \
} while(0)

// DEBUG: Printed when debug_level >= 2
#define LOG_DEBUG(fmt, ...) do { \
    if (g_debug_level >= DEBUG_LEVEL_VERBOSE) { \
        fflush(stdout); \
        DEBUG_TIMESTAMP(); \
        printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
        fflush(stdout); \
    } \
} while(0)

// TRACE: Printed when debug_level >= 3
#define LOG_TRACE(fmt, ...) do { \
    if (g_debug_level >= DEBUG_LEVEL_TRACE) { \
        fflush(stdout); \
        DEBUG_TIMESTAMP(); \
        printf("[TRACE] " fmt "\n", ##__VA_ARGS__); \
        fflush(stdout); \
    } \
} while(0)

// ============================================
// HEX DUMP MACRO (for packet debugging)
// ============================================
static inline void hex_dump(const char *desc, const void *data, size_t len) {
    if (g_debug_level < DEBUG_LEVEL_TRACE) return;

    const uint8_t *p = (const uint8_t *)data;

    fflush(stdout);
    printf("[TRACE] HEX DUMP: %s (%zu bytes)\n", desc, len);

    for (size_t i = 0; i < len; i += 16) {
        printf("  %04zx: ", i);

        // Hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", p[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }

        // ASCII
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = p[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("|\n");
    }
    fflush(stdout);
}

// ============================================
// TIMESTAMP HELPERS
// ============================================

// Convert timespec to nanoseconds
static inline uint64_t timespec_to_ns(const struct timespec *ts) {
    return (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
}

// Convert nanoseconds to microseconds (double)
static inline double ns_to_us(uint64_t ns) {
    return (double)ns / 1000.0;
}

// Get current time in nanoseconds (CLOCK_MONOTONIC)
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return timespec_to_ns(&ts);
}

// ============================================
// PRECISE DELAY (32µs between VLAN tests)
// ============================================

/**
 * Precise microsecond delay
 * Uses clock_nanosleep() - low CPU usage
 */
static inline void precise_delay_us(uint32_t microseconds) {
    struct timespec ts;
    ts.tv_sec = microseconds / 1000000;
    ts.tv_nsec = (microseconds % 1000000) * 1000;
    clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
}

/**
 * Precise microsecond delay (busy-wait version)
 * Higher precision but uses CPU
 */
static inline void precise_delay_us_busy(uint32_t microseconds) {
    uint64_t start = get_time_ns();
    uint64_t target = microseconds * 1000ULL;

    while ((get_time_ns() - start) < target) {
        // busy wait
        __asm__ volatile("pause" ::: "memory");
    }
}

// ============================================
// LATENCY RESULT STRUCTURE
// ============================================
struct latency_result {
    uint16_t tx_port;           // TX port ID
    uint16_t rx_port;           // RX port ID
    uint16_t vlan_id;           // VLAN tag
    uint16_t vl_id;             // VL-ID (MAC/IP suffix)

    uint32_t tx_count;          // Packets sent
    uint32_t rx_count;          // Packets received

    uint64_t min_latency_ns;    // Minimum latency (nanoseconds)
    uint64_t max_latency_ns;    // Maximum latency (nanoseconds)
    uint64_t total_latency_ns;  // Total latency (for average calculation)

    bool     valid;             // Valid result?
    bool     passed;            // Latency threshold check: true = PASS, false = FAIL
    char     error_msg[64];     // Error message (if any)
};

// ============================================
// TEST CONFIGURATION STRUCTURE
// ============================================
struct test_config {
    int      packet_count;      // Packet count per VLAN
    int      packet_size;       // Packet size (bytes)
    int      delay_us;          // Delay between VLAN tests (µs)
    int      timeout_ms;        // RX timeout (ms)
    int      port_filter;       // -1 = all ports, 0-7 = only this TX port
    bool     use_busy_wait;     // Use busy-wait delay
    uint64_t max_latency_ns;    // Maximum acceptable latency (ns), 0 = no check
    int      retry_count;       // Retry count on failure
};

// ============================================
// UTILITY MACROS
// ============================================
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))
#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define MAX(a, b)           ((a) > (b) ? (a) : (b))

#endif // COMMON_H

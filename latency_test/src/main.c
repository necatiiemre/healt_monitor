/**
 * @file main.c
 * @brief HW Timestamp Latency Test - Main Entry Point
 *
 * Parses command line arguments and starts the test.
 *
 * Usage:
 *   ./latency_test [options]
 *
 * Options:
 *   -n, --count <N>     Packet count per VLAN (default: 1)
 *   -s, --size <bytes>  Packet size (default: 1518)
 *   -d, --delay <us>    Delay between VLAN tests (default: 32)
 *   -T, --timeout <ms>  RX timeout (default: 5000)
 *   -p, --port <id>     Test only this TX port (default: all)
 *   -v, --verbose       Verbose output (repeat for more detail)
 *   -c, --csv           CSV format output
 *   -b, --busy-wait     Use busy-wait for precise timing
 *   -C, --check         Only check interfaces
 *   -I, --info          Show interface HW timestamp info
 *   -S, --shm           Write results to shared memory (for DPDK)
 *   -h, --help          Help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>

#include "common.h"
#include "config.h"
#include "hw_timestamp.h"
#include "latency_test.h"
#include "latency_results_shm.h"

// ============================================
// GLOBAL VARIABLES
// ============================================

int g_debug_level = DEBUG_LEVEL_NONE;
volatile int g_interrupted = 0;

// Global pointers for cleanup
static struct latency_result *g_results = NULL;
static struct latency_shm_header *g_shm = NULL;
static bool g_use_shm = false;

// ============================================
// CLEANUP
// ============================================

static void cleanup(void) {
    LOG_DEBUG("Cleaning up...");

    // Close shared memory (but don't unlink - DPDK may still need it)
    if (g_shm != NULL) {
        latency_shm_close_writer(g_shm);
        g_shm = NULL;
        LOG_DEBUG("Shared memory closed");
    }

    // Free results
    if (g_results != NULL) {
        free(g_results);
        g_results = NULL;
        LOG_DEBUG("Results memory freed");
    }

    LOG_DEBUG("Cleanup completed");
}

// ============================================
// SIGNAL HANDLER
// ============================================

static void signal_handler(int sig) {
    (void)sig;
    g_interrupted = 1;
    // Signal-safe output (ignore return value in signal handler)
    const char *msg = "\nInterrupted, cleaning up...\n";
    ssize_t ret __attribute__((unused)) = write(STDOUT_FILENO, msg, strlen(msg));
}

// ============================================
// USAGE
// ============================================

static void print_usage(const char *prog) {
    printf("HW Timestamp Latency Test\n");
    printf("==================================\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -n, --count <N>     Packet count per VLAN (default: %d)\n", DEFAULT_PACKET_COUNT);
    printf("  -s, --size <bytes>  Packet size (default: %d)\n", DEFAULT_PACKET_SIZE);
    printf("  -d, --delay <us>    Delay between VLAN tests, microseconds (default: %d)\n", DEFAULT_PACKET_INTERVAL_US);
    printf("  -T, --timeout <ms>  RX timeout, milliseconds (default: %d)\n", DEFAULT_TIMEOUT_MS);
    printf("  -p, --port <id>     Test only this TX port (0-7, default: all)\n");
    printf("  -v, --verbose       Verbose output (repeat: -vv, -vvv)\n");
    printf("  -c, --csv           CSV format output\n");
    printf("  -b, --busy-wait     Use busy-wait for precise timing\n");
    printf("  -C, --check         Only check interfaces\n");
    printf("  -I, --info          Show interface HW timestamp info\n");
    printf("  -S, --shm           Write results to shared memory (for DPDK)\n");
    printf("  -h, --help          This help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                    Test with default settings\n", prog);
    printf("  %s -n 10              10 packets per VLAN\n", prog);
    printf("  %s -n 10 -v           Test with verbose output\n", prog);
    printf("  %s -p 2 -n 5          Test only Port 2, 5 packets\n", prog);
    printf("  %s -c > results.csv   Save as CSV\n", prog);
    printf("  %s -I                 Show interface info\n", prog);
    printf("\n");
    printf("Port Mapping:\n");
    printf("  TX Port -> RX Port | Interfaces           | VLANs\n");
    printf("  ---------|---------|----------------------|----------\n");
    for (int i = 0; i < NUM_PORT_PAIRS; i++) {
        const struct port_pair *pp = &g_port_pairs[i];
        printf("  Port %d   -> Port %d | %-10s -> %-10s | %d-%d\n",
               pp->tx_port, pp->rx_port,
               pp->tx_iface, pp->rx_iface,
               pp->vlans[0], pp->vlans[pp->vlan_count - 1]);
    }
    printf("\n");
}

// ============================================
// SHOW INTERFACE INFO
// ============================================

static void show_interface_info(void) {
    printf("Interface HW Timestamp Information:\n");
    printf("===================================\n\n");

    for (int i = 0; i < NUM_PORT_PAIRS; i++) {
        const struct port_pair *pp = &g_port_pairs[i];

        printf("Port %d (%s):\n", pp->tx_port, pp->tx_iface);
        print_hw_timestamp_caps(pp->tx_iface);
    }
}

// ============================================
// MAIN
// ============================================

int main(int argc, char *argv[]) {
    // Default config
    struct test_config config = {
        .packet_count = DEFAULT_PACKET_COUNT,
        .packet_size = DEFAULT_PACKET_SIZE,
        .delay_us = DEFAULT_PACKET_INTERVAL_US,
        .timeout_ms = DEFAULT_TIMEOUT_MS,
        .port_filter = -1,
        .use_busy_wait = false,
        .max_latency_ns = DEFAULT_MAX_LATENCY_NS,
        .retry_count = DEFAULT_RETRY_COUNT
    };

    bool csv_output = false;
    bool check_only = false;
    bool show_info = false;

    // Long options
    static struct option long_options[] = {
        {"count",     required_argument, 0, 'n'},
        {"size",      required_argument, 0, 's'},
        {"delay",     required_argument, 0, 'd'},
        {"timeout",   required_argument, 0, 'T'},
        {"port",      required_argument, 0, 'p'},
        {"verbose",   no_argument,       0, 'v'},
        {"csv",       no_argument,       0, 'c'},
        {"busy-wait", no_argument,       0, 'b'},
        {"check",     no_argument,       0, 'C'},
        {"info",      no_argument,       0, 'I'},
        {"shm",       no_argument,       0, 'S'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    // Parse arguments
    int opt;
    while ((opt = getopt_long(argc, argv, "n:s:d:T:p:vcbCISh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'n':
                config.packet_count = atoi(optarg);
                if (config.packet_count < 1) {
                    fprintf(stderr, "Error: Packet count must be at least 1\n");
                    return 1;
                }
                break;

            case 's':
                config.packet_size = atoi(optarg);
                if (config.packet_size < MIN_PACKET_SIZE) {
                    fprintf(stderr, "Error: Packet size must be at least %d bytes\n", MIN_PACKET_SIZE);
                    return 1;
                }
                if (config.packet_size > MAX_PACKET_SIZE) {
                    fprintf(stderr, "Error: Packet size must be at most %d bytes\n", MAX_PACKET_SIZE);
                    return 1;
                }
                break;

            case 'd':
                config.delay_us = atoi(optarg);
                if (config.delay_us < 0) {
                    fprintf(stderr, "Error: Delay cannot be negative\n");
                    return 1;
                }
                break;

            case 'T':
                config.timeout_ms = atoi(optarg);
                if (config.timeout_ms < 100) {
                    fprintf(stderr, "Error: Timeout must be at least 100ms\n");
                    return 1;
                }
                break;

            case 'p':
                config.port_filter = atoi(optarg);
                if (config.port_filter < 0 || config.port_filter > 7) {
                    fprintf(stderr, "Error: Port ID must be between 0-7\n");
                    return 1;
                }
                break;

            case 'v':
                g_debug_level++;
                if (g_debug_level > DEBUG_LEVEL_TRACE) {
                    g_debug_level = DEBUG_LEVEL_TRACE;
                }
                break;

            case 'c':
                csv_output = true;
                break;

            case 'b':
                config.use_busy_wait = true;
                break;

            case 'C':
                check_only = true;
                break;

            case 'I':
                show_info = true;
                break;

            case 'S':
                g_use_shm = true;
                break;

            case 'h':
                print_usage(argv[0]);
                return 0;

            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Check root
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program requires root privileges.\n");
        fprintf(stderr, "       sudo %s ...\n", argv[0]);
        return 1;
    }

    // Signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Register cleanup with atexit
    atexit(cleanup);

    // Show interface info
    if (show_info) {
        show_interface_info();
        return 0;
    }

    // Check interfaces
    LOG_INFO("Checking interfaces...");
    int check_ret = check_all_interfaces();

    if (check_only) {
        if (check_ret == 0) {
            printf("All interfaces support HW timestamp.\n");
            return 0;
        } else {
            printf("Some interfaces do not support HW timestamp!\n");
            return 1;
        }
    }

    if (check_ret < 0) {
        LOG_WARN("Some interfaces do not support HW timestamp, continuing...");
    }

    // Print config
    if (!csv_output) {
        printf("\n");
        printf("HW Timestamp Latency Test\n");
        printf("=========================\n");
        printf("Packet count (per VLAN): %d\n", config.packet_count);
        printf("Packet size: %d bytes\n", config.packet_size);
        printf("Inter-VLAN delay: %d us\n", config.delay_us);
        printf("RX timeout: %d ms\n", config.timeout_ms);
        printf("Max latency threshold: %lu ns (%.1f us)\n", config.max_latency_ns, (double)config.max_latency_ns / 1000.0);
        printf("Retry count: %d\n", config.retry_count);
        printf("Port filter: %s\n", config.port_filter < 0 ? "all" : "specified");
        printf("Wait mode: %s\n", config.use_busy_wait ? "busy-wait" : "sleep");
        printf("Debug level: %d\n", g_debug_level);
        printf("\n");
    }

    // Allocate results (use global pointer for cleanup)
    g_results = calloc(MAX_RESULTS, sizeof(struct latency_result));
    if (!g_results) {
        LOG_ERROR("Failed to allocate memory for results");
        return 1;
    }

    // Initialize shared memory if requested
    if (g_use_shm) {
        LOG_INFO("Initializing shared memory for results...");
        g_shm = latency_shm_create();
        if (!g_shm) {
            LOG_ERROR("Failed to create shared memory");
            return 1;
        }
        // Store test configuration
        g_shm->packet_count = config.packet_count;
        g_shm->packet_size = config.packet_size;
        g_shm->max_latency_ns = config.max_latency_ns;
    }

    int result_count = 0;
    int attempt = 0;

    // Run test with retry mechanism
    LOG_INFO("Starting test...");
    int ret = run_latency_test_with_retry(&config, g_results, &result_count, &attempt);

    if (g_interrupted) {
        LOG_WARN("Test interrupted");
    }

    if (ret < 0 && !g_interrupted) {
        LOG_ERROR("Test failed: %d", ret);
        return 1;  // cleanup() will be called by atexit
    }

    // Print CSV results if requested (table is already printed after each attempt)
    if (result_count > 0 && csv_output) {
        // Declare function from results.c
        extern void print_results_csv(const struct latency_result *results, int result_count);
        printf("\n--- CSV EXPORT ---\n");
        print_results_csv(g_results, result_count);
    }

    // Write results to shared memory if enabled
    if (g_use_shm && g_shm && result_count > 0) {
        LOG_INFO("Writing results to shared memory...");

        // Copy results to shared memory
        // Note: struct latency_result and struct shm_latency_result have the same layout
        for (int i = 0; i < result_count; i++) {
            struct shm_latency_result shm_result;
            const struct latency_result *r = &g_results[i];

            shm_result.tx_port = r->tx_port;
            shm_result.rx_port = r->rx_port;
            shm_result.vlan_id = r->vlan_id;
            shm_result.vl_id = r->vl_id;
            shm_result.tx_count = r->tx_count;
            shm_result.rx_count = r->rx_count;
            shm_result.min_latency_ns = r->min_latency_ns;
            shm_result.max_latency_ns = r->max_latency_ns;
            shm_result.total_latency_ns = r->total_latency_ns;
            shm_result.valid = r->valid;
            shm_result.passed = r->passed;
            strncpy(shm_result.error_msg, r->error_msg, sizeof(shm_result.error_msg) - 1);

            latency_shm_write_result(g_shm, &shm_result, i);
        }

        // Finalize and mark as complete
        latency_shm_finalize(g_shm, result_count);
        LOG_INFO("Results written to shared memory '%s'", LATENCY_SHM_NAME);
    }

    LOG_INFO("Test completed (total attempts: %d)", attempt);

    return 0;  // cleanup() will be called by atexit
}

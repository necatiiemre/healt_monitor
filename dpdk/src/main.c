#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "helpers.h" // helper_reset_stats, helper_print_stats, signal_handler / force_quit
#include "port_manager.h"
#include "eal_init.h"
#include "socket.h"
#include "packet.h"
#include "tx_rx_manager.h"
#include "raw_socket_port.h"  // Raw socket port support (non-DPDK NICs)
#include "dpdk_external_tx.h" // DPDK External TX (independent system)
#include "embedded_latency/embedded_latency.h"  // Embedded HW timestamp latency test
#include "ptp_slave.h"        // PTP slave for IEEE 1588v2 synchronization

// Enable/disable raw socket ports
#ifndef ENABLE_RAW_SOCKET_PORTS
#define ENABLE_RAW_SOCKET_PORTS 1
#endif

// Enable/disable embedded HW timestamp latency test (runs BEFORE DPDK EAL init)
#ifndef EMBEDDED_HW_LATENCY_TEST
#define EMBEDDED_HW_LATENCY_TEST 1
#endif

// Check if --daemon flag is present and remove it from argv
// Returns true if --daemon was found, also updates argc
static bool check_and_remove_daemon_flag(int *argc, char const *argv[]) {
    bool found = false;
    int new_argc = 0;

    for (int i = 0; i < *argc; i++) {
        if (strcmp(argv[i], "--daemon") == 0 || strcmp(argv[i], "-d") == 0) {
            found = true;
            // Skip this argument (don't copy to new position)
        } else {
            // Keep this argument
            argv[new_argc] = argv[i];
            new_argc++;
        }
    }

    *argc = new_argc;
    return found;
}

// force_quit ve signal_handler genelde helpers.h içinde deklarasyon/definasyona sahiptir.
// Eğer sende helpers.h içinde yoksa, şu satırları açabilirsin:
// volatile bool force_quit = false;
// static void signal_handler(int sig) { (void)sig; force_quit = true; }

int main(int argc, char const *argv[])
{
    // Check for --daemon flag BEFORE anything else, and remove it from argv
    // so it doesn't confuse DPDK EAL argument parser
    bool daemon_mode = check_and_remove_daemon_flag(&argc, argv);

    // Set daemon mode flag for helper functions (disables ANSI escape codes in logs)
    helper_set_daemon_mode(daemon_mode);

    printf("=== DPDK TX/RX Application with PRBS-31 & Sequence Validation ===\n");
    if (daemon_mode) {
        printf("Mode: DAEMON (will fork to background after latency tests)\n");
    } else {
        printf("Mode: FOREGROUND (use --daemon for background mode)\n");
    }
    printf("TX Cores: %d | RX Cores: %d | VLAN: %s\n",
           NUM_TX_CORES, NUM_RX_CORES,
#if VLAN_ENABLED
           "Enabled"
#else
           "Disabled"
#endif
    );
    printf("PRBS Method: Sequence-based with ~268MB cache per port\n");
    printf("Payload format: [8-byte sequence][PRBS-31 data]\n");
    printf("WARM-UP: First 60 seconds (stats will reset at 60s)\n");
    printf("Sequence Validation: Enabled (Lost/Out-of-Order/Duplicate detection)\n");
#if ENABLE_RAW_SOCKET_PORTS
    printf("Raw Socket Ports: Enabled (%d ports, multi-target)\n", MAX_RAW_SOCKET_PORTS);
    printf("  - Port 12 (1G): 5 targets (960 Mbps total)\n");
    printf("      -> P13: 80 Mbps, P5/P4/P7/P6: 220 Mbps each\n");
    printf("  - Port 13 (100M): 1 target\n");
    printf("      -> P12: 80 Mbps\n");
#endif
#if EMBEDDED_HW_LATENCY_TEST
    printf("Embedded HW Latency Test: Enabled (runs before DPDK init)\n");
#endif
    printf("\n");

    // =========================================================================
    // EMBEDDED HW TIMESTAMP LATENCY TEST (runs BEFORE DPDK takes over NICs!)
    // Full sequence: Loopback (switch) + Unit Test (device) + Combined Results
    // =========================================================================
#if EMBEDDED_HW_LATENCY_TEST
    // Full interactive sequence:
    // 1. Loopback test (Mellanox switch latency) - or use default 14µs
    // 2. Unit test (device latency) - port pairs 0↔1, 2↔3, 4↔5, 6↔7
    // 3. Combined results: unit_latency = total - switch
    int latency_fails = emb_latency_full_sequence();

    if (emb_latency_completed()) {
        if (latency_fails > 0) {
            printf("\n*** WARNING: %d test(s) failed! ***\n\n", latency_fails);
        } else {
            printf("\n*** All latency tests PASSED! ***\n\n");
        }

        // Örnek: Port pair 0-1 için tüm gecikme değerlerini al
        // double switch_us, total_us, unit_us;
        // if (emb_latency_get_all_us(0, &switch_us, &total_us, &unit_us)) {
        //     printf("Port 0-1: Switch=%.2f µs, Total=%.2f µs, Unit=%.2f µs\n",
        //            switch_us, total_us, unit_us);
        // }

        printf("=== Latency test sequence complete ===\n");

        // daemon_mode was already set at the start of main()
        // If yes: fork to background (for remote execution from main PC)
        // If no: continue in foreground (for direct server execution)
        if (daemon_mode) {
            printf("=== Switching to background mode for DPDK operation ===\n\n");
            fflush(stdout);
            fflush(stderr);

            // Fork to background: Parent exits (SSH closes), Child continues
            pid_t pid = fork();
            if (pid < 0) {
                // Fork failed
                perror("fork failed");
                printf("Continuing in foreground mode...\n");
            } else if (pid > 0) {
                // Parent process - exit so SSH connection closes
                printf("DPDK continuing in background (PID: %d)\n", pid);
                printf("Log file: /tmp/dpdk_app.log\n");
                printf("To monitor: ssh user@server 'tail -f /tmp/dpdk_app.log'\n");
                printf("To stop: ssh user@server 'sudo pkill -f dpdk_app'\n");
                fflush(stdout);
                _exit(0);  // Use _exit to avoid flushing stdio buffers twice
            } else {
                // Child process - continue running DPDK in background
                // Create new session to detach from terminal
                setsid();

                // Redirect stdout/stderr to log file
                int log_fd = open("/tmp/dpdk_app.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (log_fd >= 0) {
                    dup2(log_fd, STDOUT_FILENO);
                    dup2(log_fd, STDERR_FILENO);
                    close(log_fd);
                }

                // Close stdin
                close(STDIN_FILENO);
                open("/dev/null", O_RDONLY);

                printf("\n=== DPDK Background Mode Started (PID: %d) ===\n", getpid());
                printf("Initializing DPDK EAL...\n\n");

                // Re-print embedded latency results to log file
                // (They were printed to terminal before fork, now save to log)
                printf("=== Embedded Latency Test Results (from interactive session) ===\n");
                emb_latency_print_combined();
                if (latency_fails > 0) {
                    printf("WARNING: %d test(s) failed!\n", latency_fails);
                } else {
                    printf("All latency tests PASSED!\n");
                }
                printf("=== End of Latency Results ===\n\n");

                fflush(stdout);
            }
        } else {
            // Foreground mode - continue normally
            printf("=== Continuing in foreground mode ===\n\n");
        }
    } else {
        printf("=== Latency test skipped, initializing DPDK ===\n\n");
    }
#endif

    // Initialize DPDK EAL
    initialize_eal(argc, argv);

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Print basic EAL info
    print_eal_info();

    // Initialize ports
    int nb_ports = initialize_ports(&ports_config);
    if (nb_ports < 0)
    {
        printf("Error: Failed to initialize ports\n");
        cleanup_eal();
        return -1;
    }

    printf("Found %d ports\n", nb_ports);

    // Setup port configuration
    set_manual_pci_addresses(&ports_config);
    portNumaNodesMatch(&ports_config);

    // Setup socket to lcore mapping
    socketToLcore();

    // Assign lcores to ports
    lcorePortAssign(&ports_config);

    // Initialize VLAN configuration + print
    init_vlan_config();
    print_vlan_config();

    // Initialize RX verification stats (PRBS good/bad/bit_errors + sequence stats)
    init_rx_stats();

    // *** PRBS-31 CACHE INITIALIZATION ***
    printf("\n=== Initializing PRBS-31 Cache ===\n");
    printf("This will take a few minutes as we generate ~%u MB per port...\n",
           (unsigned)(PRBS_CACHE_SIZE / (1024 * 1024)));

    init_prbs_cache_for_all_ports((uint16_t)nb_ports, &ports_config);

    printf("PRBS-31 cache initialization complete!\n\n");

    // Configure TX/RX for each port
    printf("\n=== Configuring Ports ===\n");
    struct txrx_config txrx_configs[MAX_PORTS];

    for (uint16_t i = 0; i < (uint16_t)nb_ports; i++)
    {
        uint16_t port_id = ports_config.ports[i].port_id;
        uint16_t socket_id = ports_config.ports[i].numa_node;

        // Create mbuf pool
        struct rte_mempool *mbuf_pool = create_mbuf_pool(socket_id, port_id);
        if (mbuf_pool == NULL)
        {
            printf("Failed to create mbuf pool for port %u\n", port_id);
            cleanup_prbs_cache();
            cleanup_ports(&ports_config);
            cleanup_eal();
            return -1;
        }

        // Setup TX/RX configuration
        txrx_configs[i].port_id = port_id;

        // Calculate number of TX queues needed
        // Base: NUM_TX_CORES (0 to NUM_TX_CORES-1)
        // External TX: +1 queue (queue 4)
        // PTP: +1 queue (queue 5)
        uint16_t num_tx_queues = NUM_TX_CORES;

#if DPDK_EXT_TX_ENABLED
        // External TX ports need an extra queue (queue 4) for external TX
        // Port 2,3,4,5 → Port 12 | Port 0,6 → Port 13
        bool is_ext_tx_port = (port_id == 0 || port_id == 2 || port_id == 3 ||
                               port_id == 4 || port_id == 5 || port_id == 6);
        if (is_ext_tx_port) {
            num_tx_queues = NUM_TX_CORES + 1;  // Extra queue for external TX (queue 4)
        }
#endif

#if PTP_ENABLED
        // PTP needs queue 5 for TX on all ports
        // Queue 5 comes after external TX queue 4
        num_tx_queues = (num_tx_queues < 6) ? 6 : num_tx_queues;  // Ensure queue 5 exists
#endif

        txrx_configs[i].nb_tx_queues = num_tx_queues;

        // Calculate number of RX queues needed
        // Base: NUM_RX_CORES (0 to NUM_RX_CORES-1)
        // PTP: +1 queue (queue 5)
        uint16_t num_rx_queues = NUM_RX_CORES;

#if PTP_ENABLED
        // PTP needs queue 5 for RX on all ports
        num_rx_queues = (num_rx_queues < 6) ? 6 : num_rx_queues;  // Ensure queue 5 exists
#endif

        txrx_configs[i].nb_rx_queues = num_rx_queues;
        txrx_configs[i].mbuf_pool = mbuf_pool;

        // Initialize port TX/RX
        int ret = init_port_txrx(port_id, &txrx_configs[i]);
        if (ret < 0)
        {
            printf("Failed to initialize TX/RX for port %u\n", port_id);
            cleanup_prbs_cache();
            cleanup_ports(&ports_config);
            cleanup_eal();
            return -1;
        }
    }

    print_ports_info(&ports_config);

    printf("All ports configured\n");

#if ENABLE_RAW_SOCKET_PORTS
    // *** RAW SOCKET PORTS INITIALIZATION ***
    printf("\n=== Initializing Raw Socket Ports (Non-DPDK) ===\n");
    printf("These ports use AF_PACKET with zero-copy (PACKET_MMAP)\n");
    printf("VLAN header: Disabled for raw socket ports\n\n");

    bool raw_ports_initialized = false;
    int raw_ret = init_raw_socket_ports();
    if (raw_ret < 0)
    {
        printf("Warning: Failed to initialize raw socket ports\n");
        printf("Continuing with DPDK ports only...\n");
    }
    else
    {
        printf("Raw socket ports initialized successfully\n");
        raw_ports_initialized = true;
    }
#endif

#if DPDK_EXT_TX_ENABLED
    // *** DPDK EXTERNAL TX INITIALIZATION (BEFORE start_txrx_workers!) ***
    // Must be called before start_txrx_workers so ext_tx_enabled can be set
    printf("\n=== Initializing DPDK External TX System ===\n");

    // Gather mbuf pools for external TX ports
    // Port order in ext_tx_configs: Port 2,3,4,5 (→P12), Port 0,6 (→P13)
    static struct dpdk_ext_tx_port_config ext_configs[] = DPDK_EXT_TX_PORTS_CONFIG_INIT;
    struct rte_mempool *ext_mbuf_pools[DPDK_EXT_TX_PORT_COUNT];
    for (int i = 0; i < DPDK_EXT_TX_PORT_COUNT; i++) {
        uint16_t port_id = ext_configs[i].port_id;
        if (port_id < nb_ports) {
            ext_mbuf_pools[i] = txrx_configs[port_id].mbuf_pool;
            printf("  Ext TX Port %u: mbuf_pool from txrx_configs[%u]\n", port_id, port_id);
        } else {
            ext_mbuf_pools[i] = NULL;
            printf("  Ext TX Port %u: mbuf_pool = NULL (port_id >= nb_ports)\n", port_id);
        }
    }

    if (dpdk_ext_tx_init(ext_mbuf_pools) != 0) {
        printf("Warning: DPDK External TX initialization failed\n");
    }
#endif

    // Start TX/RX workers
    printf("\n=== Starting Workers ===\n");
    printf("Configuration Check:\n");
    printf("  Ports detected: %d\n", nb_ports);
    printf("  TX cores per port: %d\n", NUM_TX_CORES);
    printf("  RX cores per port: %d\n", NUM_RX_CORES);
    printf("  Expected TX workers: %d\n", nb_ports * NUM_TX_CORES);
    printf("  Expected RX workers: %d\n", nb_ports * NUM_RX_CORES);
    printf("  PRBS-31 cache: Ready (~%.2f GB total)\n",
           (nb_ports * PRBS_CACHE_SIZE) / (1024.0 * 1024.0 * 1024.0));
    printf("  Payload per packet: %u bytes (SEQ: %u + PRBS: %u)\n",
           PAYLOAD_SIZE, SEQ_BYTES, NUM_PRBS_BYTES);
    printf("  Sequence Validation: ENABLED\n");
#if LATENCY_TEST_ENABLED
    printf("  Latency Test: ENABLED (will run before normal mode)\n");
#endif
    printf("\n");

#if LATENCY_TEST_ENABLED
    // *** LATENCY TEST - RUNS BEFORE NORMAL MODE ***
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║            LATENCY TEST MODE ENABLED                             ║\n");
    printf("║  Her VLAN'dan 1 paket gonderilecek, latency olculecek           ║\n");
    printf("║  Test sonrasi normal moda gecilecek                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    int latency_ret = start_latency_test(&ports_config, &force_quit);
    if (latency_ret < 0) {
        printf("Warning: Latency test failed, continuing with normal mode\n");
    }

    // Check if user pressed Ctrl+C during latency test
    if (force_quit) {
        printf("User interrupted during latency test, exiting...\n");
        cleanup_prbs_cache();
        cleanup_ports(&ports_config);
        cleanup_eal();
        return 0;
    }

    printf("\n=== Latency test complete, starting normal TX/RX workers ===\n\n");
#endif

    int start_ret = start_txrx_workers(&ports_config, &force_quit);
    if (start_ret < 0)
    {
        printf("Failed to start TX/RX workers\n");
        cleanup_prbs_cache();
        cleanup_ports(&ports_config);
        cleanup_eal();
        return -1;
    }

#if ENABLE_RAW_SOCKET_PORTS
    // Start raw socket workers (only if initialization succeeded)
    if (raw_ports_initialized)
    {
        printf("\n=== Starting Raw Socket Workers ===\n");
        start_ret = start_raw_socket_workers(&force_quit);
        if (start_ret < 0)
        {
            printf("Warning: Failed to start raw socket workers\n");
            printf("Continuing with DPDK workers only...\n");
            raw_ports_initialized = false;  // Mark as not running
        }
        else
        {
            printf("Raw socket workers started successfully\n");
        }
    }
#endif

    // Start DPDK External TX workers AFTER raw socket workers
    // This ensures Port 12 RX is ready before receiving packets from Port 2,3,4,5
#if DPDK_EXT_TX_ENABLED
    printf("\n=== Starting DPDK External TX Workers ===\n");
    printf("(Started after raw socket RX to prevent initial packet loss)\n");
    int ext_ret = dpdk_ext_tx_start_workers(&ports_config, &force_quit);
    if (ext_ret != 0)
    {
        printf("Error starting external TX workers: %d\n", ext_ret);
        // Continue anyway, this is not fatal
    }
#endif

#if PTP_ENABLED
    // *** PTP SLAVE INITIALIZATION AND START ***
    printf("\n=== Initializing PTP Slave (IEEE 1588v2) ===\n");
    printf("Mode: One-step | Transport: Layer 2 | Timestamps: Software (rte_rdtsc)\n");
    printf("Architecture: Split TX/RX Port Support\n\n");

    // Initialize PTP subsystem
    if (ptp_init() != 0) {
        printf("Warning: PTP initialization failed\n");
    } else {
        // Configure PTP sessions with split TX/RX port support
        // Sessions are defined in config.h with separate RX and TX ports
        static struct ptp_session_config ptp_sessions[] = PTP_SESSIONS_CONFIG_INIT;

        if (ptp_configure_split_sessions(ptp_sessions, PTP_SESSION_COUNT) != 0) {
            printf("Warning: Failed to configure PTP sessions\n");
        } else {
            // Assign PTP cores to RX ports (where sessions live)
            // Each unique RX port needs a dedicated lcore
            for (uint16_t i = 0; i < PTP_SESSION_COUNT; i++) {
                uint16_t rx_port_id = ptp_sessions[i].rx_port_id;

                // Find this port in ports_config and assign lcore
                for (uint16_t j = 0; j < (uint16_t)nb_ports; j++) {
                    if (ports_config.ports[j].port_id == rx_port_id &&
                        ports_config.ports[j].used_ptp_core != 0) {
                        ptp_assign_lcore(rx_port_id, ports_config.ports[j].used_ptp_core);
                        break;
                    }
                }
            }

            // Start PTP workers
            printf("\n=== Starting PTP Workers ===\n");
            if (ptp_start() != 0) {
                printf("Warning: Failed to start PTP workers\n");
            } else {
                printf("PTP workers started (%d sessions with split TX/RX ports)\n",
                       PTP_SESSION_COUNT);
            }
        }
    }
#endif

    printf("\n=== Running (Press Ctrl+C to stop) ===\n");
    printf("⚙️  WARM-UP PHASE: First 60 seconds (stats will reset)\n\n");

    // Previous TX/RX bytes for per-second rate calculation
    static uint64_t prev_tx_bytes[MAX_PORTS] = {0};
    static uint64_t prev_rx_bytes[MAX_PORTS] = {0};

    // Main loop - print stats table every second
    uint32_t loop_count = 0;
    bool warmup_complete = false;
    uint32_t test_time = 0;

    while (!force_quit)
    {
        sleep(1);
        loop_count++;

        // Warm-up tamamlanınca sıfırla
        if (loop_count == 120 && !warmup_complete)
        {
            printf("\n");
            printf("═══════════════════════════════════════════════════════════════\n");
            printf("  ✅ WARM-UP COMPLETE - RESETTING STATS - TEST STARTING NOW\n");
            printf("═══════════════════════════════════════════════════════════════\n");
            printf("\n");

            helper_reset_stats(&ports_config, prev_tx_bytes, prev_rx_bytes);

#if PTP_ENABLED
            ptp_reset_stats();
#endif

            warmup_complete = true;
            test_time = 0;

            // Görünürlük için kısa bekleme
            sleep(2);
            continue;
        }

        // Warm-up sonrası test zamanını arttır
        if (warmup_complete)
        {
            test_time++;
        }

        // Büyük tablo + kuyruk dağılımları (includes DPDK External TX stats)
        helper_print_stats(&ports_config, prev_tx_bytes, prev_rx_bytes,
                           warmup_complete, loop_count, test_time);

#if ENABLE_RAW_SOCKET_PORTS
        // Print raw socket port stats (only if initialized)
        if (raw_ports_initialized)
        {
            print_raw_socket_stats();
        }
#endif

#if PTP_ENABLED
        // Print PTP stats every second
        ptp_print_stats();
#endif

        fflush(stdout);  // Ensure output is visible on remote/main computer

        // Bir SONRAKİ saniye için prev_* güncelle: (kümülatif HW byte sayaçları)
        // helper_print_stats per-second hızları prev_* farkına göre hesaplıyor.
        for (uint16_t i = 0; i < (uint16_t)nb_ports; i++)
        {
            uint16_t port_id = ports_config.ports[i].port_id;
            struct rte_eth_stats st;
            if (rte_eth_stats_get(port_id, &st) == 0)
            {
                prev_tx_bytes[port_id] = st.obytes;
                prev_rx_bytes[port_id] = st.ibytes;
            }
        }
    }

    printf("\n=== Shutting down ===\n");

#if PTP_ENABLED
    // Stop PTP workers first
    printf("Stopping PTP workers...\n");
    ptp_print_stats();  // Final stats
    ptp_stop();
#endif

#if ENABLE_RAW_SOCKET_PORTS
    // Stop raw socket workers first (only if initialized)
    if (raw_ports_initialized)
    {
        printf("Stopping raw socket workers...\n");
        stop_raw_socket_workers();
        print_raw_socket_stats();  // Final stats
    }
#endif

    printf("Waiting 5 seconds for RX counters to flush...\n");
    sleep(15);

    // Wait for all DPDK workers to stop
    rte_eal_mp_wait_lcore();

    // Cleanup
#if PTP_ENABLED
    ptp_cleanup();
#endif

#if ENABLE_RAW_SOCKET_PORTS
    if (raw_ports_initialized)
    {
        cleanup_raw_socket_ports();
    }
#endif
    cleanup_prbs_cache();
    cleanup_ports(&ports_config);
    cleanup_eal();

    printf("Application exited cleanly\n");

    if (warmup_complete)
    {
        printf("\n📊 Total test duration: %u seconds (after warm-up)\n", test_time);
    }

    return 0;
}
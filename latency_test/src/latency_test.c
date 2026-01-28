/**
 * @file latency_test.c
 * @brief HW Timestamp Latency Test - Test Logic Implementation
 *
 * Ana test mantığı:
 * - Her port çifti için soket aç (bir kez)
 * - Her VLAN için paket gönder/al
 * - VLAN testleri arasında 32µs bekle
 * - Latency hesapla
 * - Soketleri kapat
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "latency_test.h"
#include "hw_timestamp.h"
#include "packet.h"
#include "common.h"
#include "config.h"

// Forward declaration for results printing (defined in results.c)
extern void print_results_table_with_attempt(const struct latency_result *results,
                                              int result_count, int packet_count, int attempt);

// Interrupt flag (defined in main.c)
extern volatile int g_interrupted;

// ============================================
// CHECK INTERFACES
// ============================================

int check_all_interfaces(void) {
    LOG_INFO("Checking HW timestamp support for all interfaces...");

    int failed = 0;

    for (int i = 0; i < NUM_PORT_PAIRS; i++) {
        const struct port_pair *pp = &g_port_pairs[i];

        // Check TX interface
        if (!check_hw_timestamp_support(pp->tx_iface)) {
            LOG_ERROR("TX interface %s (Port %d) does not support HW timestamp",
                     pp->tx_iface, pp->tx_port);
            failed++;
        }

        // Check RX interface
        if (!check_hw_timestamp_support(pp->rx_iface)) {
            LOG_ERROR("RX interface %s (Port %d) does not support HW timestamp",
                     pp->rx_iface, pp->rx_port);
            failed++;
        }
    }

    if (failed > 0) {
        LOG_ERROR("%d interfaces failed HW timestamp check", failed);
        return -1;
    }

    LOG_INFO("All interfaces support HW timestamp");
    return 0;
}

// ============================================
// SINGLE VLAN TEST (with pre-opened sockets)
// ============================================

static int run_single_vlan_test(
    struct hw_socket *tx_sock,
    struct hw_socket *rx_sock,
    uint16_t tx_port,
    uint16_t rx_port,
    uint16_t vlan_id,
    uint16_t vl_id,
    const struct test_config *config,
    struct latency_result *result)
{
    // Initialize result
    memset(result, 0, sizeof(*result));
    result->tx_port = tx_port;
    result->rx_port = rx_port;
    result->vlan_id = vlan_id;
    result->vl_id = vl_id;
    result->min_latency_ns = UINT64_MAX;
    result->valid = false;

    LOG_DEBUG("Testing VLAN %u (VL-ID %u): Port %d -> Port %d",
             vlan_id, vl_id, tx_port, rx_port);

    // Packet buffer
    uint8_t pkt_buf[2048];
    uint8_t rx_buf[2048];

    // Send packets one by one and receive response
    for (int pkt = 0; pkt < config->packet_count && !g_interrupted; pkt++) {
        uint64_t seq_num = (uint64_t)vlan_id << 32 | (uint64_t)pkt;

        // Build packet
        int pkt_len = build_test_packet(pkt_buf, config->packet_size,
                                        vlan_id, vl_id, seq_num);
        if (pkt_len < 0) {
            LOG_ERROR("Failed to build packet %d for VLAN %u", pkt, vlan_id);
            continue;
        }

        // Send and get TX timestamp
        uint64_t tx_ts = 0;
        int ret = send_packet_get_tx_timestamp(tx_sock, pkt_buf, pkt_len, &tx_ts);

        if (ret < 0) {
            if (ret == -10) {
                LOG_DEBUG("TX interrupted");
                break;
            }
            LOG_WARN("TX[%d]: Failed to send/get timestamp (ret=%d)", pkt, ret);
            result->tx_count++;
            continue;
        }

        result->tx_count++;
        LOG_TRACE("TX[%d]: seq=%lu, ts=%lu ns", pkt, seq_num, tx_ts);

        // Now wait for RX packet
        uint64_t start_time = get_time_ns();
        int remaining_timeout = config->timeout_ms;
        bool received = false;

        while (remaining_timeout > 0 && !received && !g_interrupted) {
            size_t rx_len = sizeof(rx_buf);
            uint64_t rx_ts = 0;

            ret = recv_packet_get_rx_timestamp(rx_sock, rx_buf, &rx_len, &rx_ts,
                                               MIN(100, remaining_timeout));

            if (ret == -1) {
                // Timeout, check remaining
                uint64_t elapsed_ms = (get_time_ns() - start_time) / 1000000;
                remaining_timeout = config->timeout_ms - (int)elapsed_ms;
                continue;
            }

            if (ret == -10) {
                LOG_DEBUG("RX interrupted");
                break;
            }

            if (ret < 0) {
                LOG_TRACE("RX error: %d", ret);
                continue;
            }

            // Check if this is our packet
            if (!is_our_test_packet(rx_buf, rx_len, vlan_id, vl_id)) {
                LOG_TRACE("Received non-matching packet (len=%zu), skipping", rx_len);
                continue;
            }

            // Extract sequence number
            uint64_t rx_seq = extract_seq_num(rx_buf, rx_len);

            if (rx_seq != seq_num) {
                LOG_TRACE("Sequence mismatch: expected=%lu, got=%lu", seq_num, rx_seq);
                continue;
            }

            // Packet matched!
            received = true;
            result->rx_count++;

            // Calculate latency
            if (rx_ts > 0 && tx_ts > 0) {
                uint64_t latency = rx_ts - tx_ts;

                result->total_latency_ns += latency;
                if (latency < result->min_latency_ns) {
                    result->min_latency_ns = latency;
                }
                if (latency > result->max_latency_ns) {
                    result->max_latency_ns = latency;
                }

                LOG_DEBUG("Pkt[%d] Latency: %lu ns (%.2f us)", pkt, latency, ns_to_us(latency));
            } else {
                LOG_WARN("Pkt[%d] Missing timestamp: tx_ts=%lu, rx_ts=%lu", pkt, tx_ts, rx_ts);
            }
        }

        if (!received && !g_interrupted) {
            LOG_DEBUG("Pkt[%d] No response received (timeout)", pkt);
        }
    }

    // Finalize result
    if (result->rx_count > 0) {
        result->valid = true;
        if (result->min_latency_ns == UINT64_MAX) {
            result->min_latency_ns = 0;
        }

        // Check against threshold (use max latency for pass/fail decision)
        if (config->max_latency_ns > 0) {
            result->passed = (result->max_latency_ns <= config->max_latency_ns);
        } else {
            result->passed = true;  // No threshold = always pass if packets received
        }
    } else {
        snprintf(result->error_msg, sizeof(result->error_msg), "No packets received");
        result->passed = false;  // No packets = FAIL
    }

    LOG_INFO("VLAN %u: TX=%u, RX=%u, Min=%.2f us, Avg=%.2f us, Max=%.2f us, %s",
            vlan_id, result->tx_count, result->rx_count,
            ns_to_us(result->min_latency_ns),
            result->rx_count > 0 ? ns_to_us(result->total_latency_ns / result->rx_count) : 0.0,
            ns_to_us(result->max_latency_ns),
            result->passed ? "PASS" : "FAIL");

    return 0;
}

// ============================================
// PORT PAIR TEST
// ============================================

int run_port_pair_test(const struct port_pair *pair,
                       const struct test_config *config,
                       struct latency_result *results) {

    LOG_INFO("Testing port pair: Port %d (%s) -> Port %d (%s)",
            pair->tx_port, pair->tx_iface,
            pair->rx_port, pair->rx_iface);

    // Open sockets ONCE for the entire port pair
    struct hw_socket tx_sock, rx_sock;

    int ret = create_hw_timestamp_socket(pair->tx_iface, SOCK_TYPE_TX, &tx_sock);
    if (ret < 0) {
        LOG_ERROR("Failed to create TX socket for %s: %d", pair->tx_iface, ret);
        // Fill all results with error
        for (int v = 0; v < pair->vlan_count; v++) {
            memset(&results[v], 0, sizeof(results[v]));
            results[v].tx_port = pair->tx_port;
            results[v].rx_port = pair->rx_port;
            results[v].vlan_id = pair->vlans[v];
            results[v].vl_id = pair->vl_ids[v];
            snprintf(results[v].error_msg, sizeof(results[v].error_msg), "TX socket error");
        }
        return -1;
    }

    ret = create_hw_timestamp_socket(pair->rx_iface, SOCK_TYPE_RX, &rx_sock);
    if (ret < 0) {
        LOG_ERROR("Failed to create RX socket for %s: %d", pair->rx_iface, ret);
        close_hw_timestamp_socket(&tx_sock);
        for (int v = 0; v < pair->vlan_count; v++) {
            memset(&results[v], 0, sizeof(results[v]));
            results[v].tx_port = pair->tx_port;
            results[v].rx_port = pair->rx_port;
            results[v].vlan_id = pair->vlans[v];
            results[v].vl_id = pair->vl_ids[v];
            snprintf(results[v].error_msg, sizeof(results[v].error_msg), "RX socket error");
        }
        return -2;
    }

    // Small delay to let sockets fully initialize before first packet
    // This prevents the first VLAN test from failing
    // 10ms seems to be needed for reliable first packet reception
    usleep(10000);  // 10ms
    LOG_DEBUG("Sockets ready, starting VLAN tests");

    // Test each VLAN
    for (int v = 0; v < pair->vlan_count && !g_interrupted; v++) {
        run_single_vlan_test(
            &tx_sock, &rx_sock,
            pair->tx_port, pair->rx_port,
            pair->vlans[v], pair->vl_ids[v],
            config, &results[v]);

        // 32µs delay between VLAN tests (except after last one)
        if (v < pair->vlan_count - 1 && !g_interrupted) {
            LOG_TRACE("Waiting %d us before next VLAN test...", config->delay_us);

            if (config->use_busy_wait) {
                precise_delay_us_busy(config->delay_us);
            } else {
                precise_delay_us(config->delay_us);
            }
        }
    }

    // Close sockets
    close_hw_timestamp_socket(&tx_sock);
    close_hw_timestamp_socket(&rx_sock);

    return 0;
}

// ============================================
// MAIN TEST FUNCTION
// ============================================

int run_latency_test(const struct test_config *config,
                     struct latency_result *results,
                     int *result_count) {

    LOG_INFO("Starting latency test...");
    LOG_INFO("  Packet count per VLAN: %d", config->packet_count);
    LOG_INFO("  Packet size: %d bytes", config->packet_size);
    LOG_INFO("  Inter-VLAN delay: %d us", config->delay_us);
    LOG_INFO("  RX timeout: %d ms", config->timeout_ms);
    if (config->port_filter >= 0) {
        LOG_INFO("  Port filter: %d", config->port_filter);
    } else {
        LOG_INFO("  Port filter: all");
    }

    *result_count = 0;

    for (int p = 0; p < NUM_PORT_PAIRS && !g_interrupted; p++) {
        const struct port_pair *pair = &g_port_pairs[p];

        // Port filter
        if (config->port_filter >= 0 && pair->tx_port != config->port_filter) {
            LOG_DEBUG("Skipping port pair %d (filter=%d)", pair->tx_port, config->port_filter);
            continue;
        }

        run_port_pair_test(pair, config, &results[*result_count]);
        *result_count += pair->vlan_count;

        // Delay between port pairs
        if (p < NUM_PORT_PAIRS - 1 && !g_interrupted) {
            LOG_TRACE("Waiting %d us before next port pair...", config->delay_us);

            if (config->use_busy_wait) {
                precise_delay_us_busy(config->delay_us);
            } else {
                precise_delay_us(config->delay_us);
            }
        }
    }

    LOG_INFO("Latency test completed. Total results: %d", *result_count);

    return 0;
}

// Legacy function for compatibility
int run_vlan_test(const struct port_pair *pair,
                  int vlan_idx,
                  const struct test_config *config,
                  struct latency_result *result) {
    // Open sockets
    struct hw_socket tx_sock, rx_sock;

    int ret = create_hw_timestamp_socket(pair->tx_iface, SOCK_TYPE_TX, &tx_sock);
    if (ret < 0) return -1;

    ret = create_hw_timestamp_socket(pair->rx_iface, SOCK_TYPE_RX, &rx_sock);
    if (ret < 0) {
        close_hw_timestamp_socket(&tx_sock);
        return -2;
    }

    ret = run_single_vlan_test(
        &tx_sock, &rx_sock,
        pair->tx_port, pair->rx_port,
        pair->vlans[vlan_idx], pair->vl_ids[vlan_idx],
        config, result);

    close_hw_timestamp_socket(&tx_sock);
    close_hw_timestamp_socket(&rx_sock);

    return ret;
}

// ============================================
// RETRY MECHANISM
// ============================================

int count_failed_results(const struct latency_result *results, int result_count) {
    int fail_count = 0;
    for (int i = 0; i < result_count; i++) {
        if (!results[i].passed) {
            fail_count++;
        }
    }
    return fail_count;
}

int run_latency_test_with_retry(const struct test_config *config,
                                struct latency_result *results,
                                int *result_count,
                                int *attempt_out) {
    int max_attempts = 1 + config->retry_count;  // 1 initial + retry_count retries
    int fail_count = 0;

    for (int attempt = 1; attempt <= max_attempts && !g_interrupted; attempt++) {
        *attempt_out = attempt;

        if (attempt > 1) {
            printf("\n");
            LOG_WARN("========================================");
            LOG_WARN("=== RETRY %d/%d (previous FAIL: %d) ===",
                    attempt - 1, config->retry_count, fail_count);
            LOG_WARN("========================================");
            printf("\n");
        }

        // Clear results for new attempt
        memset(results, 0, MAX_RESULTS * sizeof(struct latency_result));
        *result_count = 0;

        // Run the test
        int ret = run_latency_test(config, results, result_count);

        if (ret < 0) {
            LOG_ERROR("Test failed with error: %d", ret);
            return ret;
        }

        // Count failures
        fail_count = count_failed_results(results, *result_count);

        // Print results table for this attempt
        print_results_table_with_attempt(results, *result_count, config->packet_count, attempt);

        if (fail_count == 0) {
            LOG_INFO("All tests PASS (attempt %d/%d)", attempt, max_attempts);
            return 0;  // All passed
        }

        // If this is not the last attempt, we'll retry
        if (attempt < max_attempts) {
            LOG_WARN("FAIL count: %d, retrying...", fail_count);
            // Small delay before retry
            usleep(100000);  // 100ms
        }
    }

    // Exhausted all retries
    LOG_WARN("All attempts completed, still %d FAIL remaining", fail_count);
    return fail_count;
}

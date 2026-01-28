/**
 * @file latency_test.h
 * @brief HW Timestamp Latency Test - Test Logic API
 */

#ifndef LATENCY_TEST_H
#define LATENCY_TEST_H

#include "common.h"
#include "config.h"

// ============================================
// TOTAL RESULTS COUNT
// ============================================
#define MAX_RESULTS     (NUM_PORT_PAIRS * MAX_VLANS_PER_PAIR)  // 8 * 4 = 32

// ============================================
// FUNCTION DECLARATIONS
// ============================================

/**
 * Check HW timestamp support for all interfaces
 *
 * @return  0 = all supported, <0 = some not supported
 */
int check_all_interfaces(void);

/**
 * Run latency test
 *
 * @param config    Test configuration
 * @param results   Results array (at least MAX_RESULTS elements)
 * @param result_count  Output: valid result count
 * @return          0 = success, <0 = error
 */
int run_latency_test(const struct test_config *config,
                     struct latency_result *results,
                     int *result_count);

/**
 * Run test for a single port pair
 *
 * @param pair      Port pair
 * @param config    Test configuration
 * @param results   Results array (at least pair->vlan_count elements)
 * @return          0 = success, <0 = error
 */
int run_port_pair_test(const struct port_pair *pair,
                       const struct test_config *config,
                       struct latency_result *results);

/**
 * Run test for a single VLAN
 *
 * @param pair      Port pair
 * @param vlan_idx  VLAN index (0-3)
 * @param config    Test configuration
 * @param result    Result
 * @return          0 = success, <0 = error
 */
int run_vlan_test(const struct port_pair *pair,
                  int vlan_idx,
                  const struct test_config *config,
                  struct latency_result *result);

/**
 * Latency test with retry mechanism
 * If there are failed tests, retries the specified number of times
 *
 * @param config        Test configuration
 * @param results       Results array (at least MAX_RESULTS elements)
 * @param result_count  Output: valid result count
 * @param attempt_out   Output: which attempt completed (1 = first attempt)
 * @return              0 = all tests PASS, >0 = FAIL count, <0 = error
 */
int run_latency_test_with_retry(const struct test_config *config,
                                struct latency_result *results,
                                int *result_count,
                                int *attempt_out);

/**
 * Count FAIL results
 *
 * @param results       Results array
 * @param result_count  Result count
 * @return              Number of failed tests
 */
int count_failed_results(const struct latency_result *results, int result_count);

#endif // LATENCY_TEST_H

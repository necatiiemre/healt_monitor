/**
 * @file results.c
 * @brief HW Timestamp Latency Test - Results Output
 *
 * ASCII tablo formatında sonuç gösterimi (DPDK formatı ile uyumlu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "common.h"
#include "config.h"
#include "latency_test.h"

// ============================================
// TABLE CHARACTERS (Unicode box drawing)
// ============================================
#define TBL_TL  "╔"   // Top-left
#define TBL_TR  "╗"   // Top-right
#define TBL_BL  "╚"   // Bottom-left
#define TBL_BR  "╝"   // Bottom-right
#define TBL_H   "═"   // Horizontal
#define TBL_V   "║"   // Vertical
#define TBL_TH  "╦"   // T-horizontal (top)
#define TBL_BH  "╩"   // T-horizontal (bottom)
#define TBL_TV  "╠"   // T-vertical (left)
#define TBL_TVR "╣"   // T-vertical (right)
#define TBL_X   "╬"   // Cross

// Column widths
#define COL_PORT    8
#define COL_VLAN    10
#define COL_VLID    10
#define COL_LAT     11
#define COL_RXTX    10
#define COL_RESULT  8

// Total width (without outer borders)
#define TABLE_WIDTH (COL_PORT + COL_PORT + COL_VLAN + COL_VLID + COL_LAT + COL_LAT + COL_LAT + COL_RXTX + COL_RESULT + 8)

// ============================================
// HELPER FUNCTIONS
// ============================================

static void print_horizontal_line(const char *left, const char *mid, const char *right, const char *fill) {
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

static void print_title_line(const char *title) {
    int title_len = strlen(title);
    int padding = (TABLE_WIDTH - title_len) / 2;

    printf("%s", TBL_V);
    for (int i = 0; i < padding; i++) printf(" ");
    printf("%s", title);
    for (int i = 0; i < TABLE_WIDTH - padding - title_len; i++) printf(" ");
    printf("%s\n", TBL_V);
}

// ============================================
// MAIN PRINT FUNCTION
// ============================================

void print_results_table(const struct latency_result *results, int result_count, int packet_count) {
    // Statistics
    int successful = 0;
    int passed_count = 0;
    double total_avg_latency = 0.0;
    double min_of_mins = 1e9;
    double max_of_maxs = 0.0;

    // Count successful and passed
    for (int i = 0; i < result_count; i++) {
        if (results[i].rx_count > 0) {
            successful++;
            double avg = ns_to_us(results[i].total_latency_ns / results[i].rx_count);
            total_avg_latency += avg;

            double min_lat = ns_to_us(results[i].min_latency_ns);
            double max_lat = ns_to_us(results[i].max_latency_ns);
            if (min_lat < min_of_mins) min_of_mins = min_lat;
            if (max_lat > max_of_maxs) max_of_maxs = max_lat;
        }
        if (results[i].passed) {
            passed_count++;
        }
    }

    // Print table
    fflush(stdout);
    printf("\n");

    // Top border
    print_horizontal_line(TBL_TL, TBL_TH, TBL_TR, TBL_H);

    // Title
    print_title_line("LATENCY TEST RESULTS (Timestamp: HARDWARE NIC)");

    // Header separator
    print_horizontal_line(TBL_TV, TBL_X, TBL_TVR, TBL_H);

    // Header row
    printf("%s%*s%s%*s%s%*s%s%*s%s%*s%s%*s%s%*s%s%*s%s%*s%s\n",
           TBL_V, COL_PORT, "TX Port",
           TBL_V, COL_PORT, "RX Port",
           TBL_V, COL_VLAN, "VLAN",
           TBL_V, COL_VLID, "VL-ID",
           TBL_V, COL_LAT, "Min (us)",
           TBL_V, COL_LAT, "Avg (us)",
           TBL_V, COL_LAT, "Max (us)",
           TBL_V, COL_RXTX, "RX/TX",
           TBL_V, COL_RESULT, "Result",
           TBL_V);

    // Header bottom separator
    print_horizontal_line(TBL_TV, TBL_X, TBL_TVR, TBL_H);

    // Data rows
    for (int i = 0; i < result_count; i++) {
        const struct latency_result *r = &results[i];

        char min_str[16], avg_str[16], max_str[16], rxtx_str[16];
        const char *result_str = r->passed ? "PASS" : "FAIL";

        if (r->rx_count > 0) {
            snprintf(min_str, sizeof(min_str), "%9.2f", ns_to_us(r->min_latency_ns));
            snprintf(avg_str, sizeof(avg_str), "%9.2f", ns_to_us(r->total_latency_ns / r->rx_count));
            snprintf(max_str, sizeof(max_str), "%9.2f", ns_to_us(r->max_latency_ns));
        } else {
            snprintf(min_str, sizeof(min_str), "%9s", "-");
            snprintf(avg_str, sizeof(avg_str), "%9s", "-");
            snprintf(max_str, sizeof(max_str), "%9s", "-");
        }

        snprintf(rxtx_str, sizeof(rxtx_str), "%4u/%-4u", r->rx_count, r->tx_count);

        printf("%s%*u%s%*u%s%*u%s%*u%s%*s%s%*s%s%*s%s%*s%s%*s%s\n",
               TBL_V, COL_PORT, r->tx_port,
               TBL_V, COL_PORT, r->rx_port,
               TBL_V, COL_VLAN, r->vlan_id,
               TBL_V, COL_VLID, r->vl_id,
               TBL_V, COL_LAT, min_str,
               TBL_V, COL_LAT, avg_str,
               TBL_V, COL_LAT, max_str,
               TBL_V, COL_RXTX, rxtx_str,
               TBL_V, COL_RESULT, result_str,
               TBL_V);
    }

    // Summary separator
    print_horizontal_line(TBL_TV, TBL_BH, TBL_TVR, TBL_H);

    // Summary line
    char summary[128];
    if (successful > 0) {
        snprintf(summary, sizeof(summary),
                "SUMMARY: PASS %d/%d | Avg: %.2f us | Max: %.2f us | Packets/VLAN: %d",
                passed_count, result_count,
                total_avg_latency / successful,
                max_of_maxs,
                packet_count);
    } else {
        snprintf(summary, sizeof(summary),
                "SUMMARY: PASS %d/%d | Packets/VLAN: %d",
                passed_count, result_count, packet_count);
    }
    print_title_line(summary);

    // Bottom border
    print_horizontal_line(TBL_BL, TBL_BH, TBL_BR, TBL_H);

    printf("\n");

    // Additional stats if verbose
    if (g_debug_level >= DEBUG_LEVEL_INFO && successful > 0) {
        printf("Additional Statistics:\n");
        printf("  Minimum latency (all VLANs): %.2f us\n", min_of_mins);
        printf("  Maximum latency (all VLANs): %.2f us\n", max_of_maxs);
        printf("  Successful VLAN ratio: %.1f%%\n", (100.0 * successful) / result_count);
        printf("\n");
    }
    fflush(stdout);
}

// ============================================
// PRINT WITH ATTEMPT INFO
// ============================================

void print_results_table_with_attempt(const struct latency_result *results,
                                       int result_count, int packet_count, int attempt) {
    fflush(stdout);
    // Statistics
    int successful = 0;
    int passed_count = 0;
    double total_avg_latency = 0.0;
    double min_of_mins = 1e9;
    double max_of_maxs = 0.0;

    // Count successful and passed
    for (int i = 0; i < result_count; i++) {
        if (results[i].rx_count > 0) {
            successful++;
            double avg = ns_to_us(results[i].total_latency_ns / results[i].rx_count);
            total_avg_latency += avg;

            double min_lat = ns_to_us(results[i].min_latency_ns);
            double max_lat = ns_to_us(results[i].max_latency_ns);
            if (min_lat < min_of_mins) min_of_mins = min_lat;
            if (max_lat > max_of_maxs) max_of_maxs = max_lat;
        }
        if (results[i].passed) {
            passed_count++;
        }
    }

    // Print table
    printf("\n");

    // Top border
    print_horizontal_line(TBL_TL, TBL_TH, TBL_TR, TBL_H);

    // Title with attempt info
    char title[128];
    if (attempt > 1) {
        snprintf(title, sizeof(title),
                "LATENCY TEST RESULTS (HW Timestamp) - Attempt %d", attempt);
    } else {
        snprintf(title, sizeof(title),
                "LATENCY TEST RESULTS (Timestamp: HARDWARE NIC)");
    }
    print_title_line(title);

    // Header separator
    print_horizontal_line(TBL_TV, TBL_X, TBL_TVR, TBL_H);

    // Header row
    printf("%s%*s%s%*s%s%*s%s%*s%s%*s%s%*s%s%*s%s%*s%s%*s%s\n",
           TBL_V, COL_PORT, "TX Port",
           TBL_V, COL_PORT, "RX Port",
           TBL_V, COL_VLAN, "VLAN",
           TBL_V, COL_VLID, "VL-ID",
           TBL_V, COL_LAT, "Min (us)",
           TBL_V, COL_LAT, "Avg (us)",
           TBL_V, COL_LAT, "Max (us)",
           TBL_V, COL_RXTX, "RX/TX",
           TBL_V, COL_RESULT, "Result",
           TBL_V);

    // Header bottom separator
    print_horizontal_line(TBL_TV, TBL_X, TBL_TVR, TBL_H);

    // Data rows
    for (int i = 0; i < result_count; i++) {
        const struct latency_result *r = &results[i];

        char min_str[16], avg_str[16], max_str[16], rxtx_str[16];
        const char *result_str = r->passed ? "PASS" : "FAIL";

        if (r->rx_count > 0) {
            snprintf(min_str, sizeof(min_str), "%9.2f", ns_to_us(r->min_latency_ns));
            snprintf(avg_str, sizeof(avg_str), "%9.2f", ns_to_us(r->total_latency_ns / r->rx_count));
            snprintf(max_str, sizeof(max_str), "%9.2f", ns_to_us(r->max_latency_ns));
        } else {
            snprintf(min_str, sizeof(min_str), "%9s", "-");
            snprintf(avg_str, sizeof(avg_str), "%9s", "-");
            snprintf(max_str, sizeof(max_str), "%9s", "-");
        }

        snprintf(rxtx_str, sizeof(rxtx_str), "%4u/%-4u", r->rx_count, r->tx_count);

        printf("%s%*u%s%*u%s%*u%s%*u%s%*s%s%*s%s%*s%s%*s%s%*s%s\n",
               TBL_V, COL_PORT, r->tx_port,
               TBL_V, COL_PORT, r->rx_port,
               TBL_V, COL_VLAN, r->vlan_id,
               TBL_V, COL_VLID, r->vl_id,
               TBL_V, COL_LAT, min_str,
               TBL_V, COL_LAT, avg_str,
               TBL_V, COL_LAT, max_str,
               TBL_V, COL_RXTX, rxtx_str,
               TBL_V, COL_RESULT, result_str,
               TBL_V);
    }

    // Summary separator
    print_horizontal_line(TBL_TV, TBL_BH, TBL_TVR, TBL_H);

    // Summary line with attempt info
    char summary[128];
    if (successful > 0) {
        snprintf(summary, sizeof(summary),
                "SUMMARY: PASS %d/%d | Avg: %.2f us | Max: %.2f us | Pkt: %d | Attempt: %d",
                passed_count, result_count,
                total_avg_latency / successful,
                max_of_maxs,
                packet_count, attempt);
    } else {
        snprintf(summary, sizeof(summary),
                "SUMMARY: PASS %d/%d | Packets/VLAN: %d | Attempt: %d",
                passed_count, result_count, packet_count, attempt);
    }
    print_title_line(summary);

    // Bottom border
    print_horizontal_line(TBL_BL, TBL_BH, TBL_BR, TBL_H);

    printf("\n");

    // Additional stats if verbose
    if (g_debug_level >= DEBUG_LEVEL_INFO && successful > 0) {
        printf("Additional Statistics:\n");
        printf("  Minimum latency (all VLANs): %.2f us\n", min_of_mins);
        printf("  Maximum latency (all VLANs): %.2f us\n", max_of_maxs);
        printf("  Successful VLAN ratio: %.1f%%\n", (100.0 * successful) / result_count);
        if (attempt > 1) {
            printf("  Test completed (attempt %d)\n", attempt);
        }
        printf("\n");
    }
    fflush(stdout);
}

// ============================================
// BRIEF SUMMARY
// ============================================

void print_brief_summary(const struct latency_result *results, int result_count) {
    int successful = 0;
    int total_rx = 0, total_tx = 0;
    double total_latency = 0.0;

    for (int i = 0; i < result_count; i++) {
        total_tx += results[i].tx_count;
        total_rx += results[i].rx_count;
        if (results[i].rx_count > 0) {
            successful++;
            total_latency += ns_to_us(results[i].total_latency_ns / results[i].rx_count);
        }
    }

    printf("\n=== SUMMARY ===\n");
    printf("Total VLANs: %d\n", result_count);
    printf("Successful: %d (%.1f%%)\n", successful, (100.0 * successful) / result_count);
    printf("Total TX: %d packets\n", total_tx);
    printf("Total RX: %d packets (%.1f%%)\n", total_rx, total_tx > 0 ? (100.0 * total_rx) / total_tx : 0.0);
    if (successful > 0) {
        printf("Average Latency: %.2f us\n", total_latency / successful);
    }
    printf("===============\n\n");
}

// ============================================
// CSV EXPORT (optional)
// ============================================

void print_results_csv(const struct latency_result *results, int result_count) {
    printf("tx_port,rx_port,vlan,vl_id,min_us,avg_us,max_us,rx_count,tx_count,passed\n");

    for (int i = 0; i < result_count; i++) {
        const struct latency_result *r = &results[i];

        double min_us = r->rx_count > 0 ? ns_to_us(r->min_latency_ns) : 0;
        double avg_us = r->rx_count > 0 ? ns_to_us(r->total_latency_ns / r->rx_count) : 0;
        double max_us = r->rx_count > 0 ? ns_to_us(r->max_latency_ns) : 0;

        printf("%u,%u,%u,%u,%.2f,%.2f,%.2f,%u,%u,%s\n",
               r->tx_port, r->rx_port, r->vlan_id, r->vl_id,
               min_us, avg_us, max_us,
               r->rx_count, r->tx_count,
               r->passed ? "PASS" : "FAIL");
    }
}

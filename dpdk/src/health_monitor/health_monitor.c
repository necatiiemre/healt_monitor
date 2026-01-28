#define _GNU_SOURCE
#include "health_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <poll.h>

// ==========================================
// GLOBAL STATE
// ==========================================

static struct health_monitor_state g_health_monitor;
static volatile bool *g_stop_flag = NULL;

// ==========================================
// QUERY PACKET TEMPLATE (64 bytes, no VLAN)
// ==========================================

static const uint8_t health_query_template[HEALTH_MONITOR_QUERY_SIZE] = {
    // Ethernet Header (14 bytes)
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00,  // DST MAC (multicast)
    0x02, 0x00, 0x00, 0x00, 0x00, 0x20,  // SRC MAC
    0x08, 0x00,                          // EtherType (IPv4)

    // IP Header (20 bytes)
    0x45, 0x00, 0x00, 0x32,              // Version, IHL, TOS, Total Length (50)
    0xd4, 0x3b, 0x00, 0x00,              // ID, Flags, Fragment Offset
    0x01, 0x11,                          // TTL=1, Protocol=UDP
    0xd9, 0x9d,                          // Header Checksum
    0x0a, 0x01, 0x21, 0x01,              // SRC IP: 10.1.33.1
    0xe0, 0xe0, 0x00, 0x00,              // DST IP: 224.224.0.0

    // UDP Header (8 bytes)
    0x00, 0x64, 0x00, 0x64,              // SRC Port: 100, DST Port: 100
    0x00, 0x1e, 0x00, 0x00,              // Length: 30, Checksum: 0

    // Payload (22 bytes)
    0x7e, 0x00, 0x52, 0x00, 0x00, 0x00,
    0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // Sequence Number (1 byte) - offset 63
    0x2f
};

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

static uint64_t get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void hex_dump(const char *prefix, const uint8_t *data, size_t len)
{
    printf("%s (len=%zu):\n", prefix, len);

    for (size_t i = 0; i < len; i += 16) {
        printf("  %04zx: ", i);

        // Hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }

        printf("\n");
    }
}

static int get_interface_index(const char *ifname)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return ifr.ifr_ifindex;
}

// ==========================================
// SOCKET FUNCTIONS
// ==========================================

static int create_raw_socket(const char *ifname, int if_index)
{
    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(stderr, "[HEALTH] Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    // Bind to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_index;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "[HEALTH] Failed to bind socket: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    // Set promiscuous mode for RX
    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = if_index;
    mreq.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        fprintf(stderr, "[HEALTH] Warning: Failed to set promiscuous mode: %s\n", strerror(errno));
        // Continue anyway
    }

    return sock;
}

// ==========================================
// PACKET FUNCTIONS
// ==========================================

static int send_health_query(void)
{
    struct health_monitor_state *state = &g_health_monitor;

    // Update sequence number in packet
    state->query_packet[63] = state->sequence;

    // Setup destination address
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = state->if_index;
    dest.sll_halen = ETH_ALEN;
    memcpy(dest.sll_addr, state->query_packet, ETH_ALEN);  // DST MAC

    // Send packet
    ssize_t sent = sendto(state->tx_socket, state->query_packet, HEALTH_MONITOR_QUERY_SIZE,
                          0, (struct sockaddr *)&dest, sizeof(dest));

    if (sent < 0) {
        fprintf(stderr, "[HEALTH] Failed to send query: %s\n", strerror(errno));
        return -1;
    }

    printf("[HEALTH] Query sent (seq=0x%02X)\n", state->sequence);
    return 0;
}

static bool is_health_response(const uint8_t *packet, size_t len)
{
    // Minimum packet size check
    if (len < 14) return false;

    // Check VL_IDX at DST MAC offset 4-5
    if (packet[4] == HEALTH_MONITOR_RESPONSE_VL_IDX_HIGH &&
        packet[5] == HEALTH_MONITOR_RESPONSE_VL_IDX_LOW) {
        return true;
    }

    return false;
}

static int receive_health_responses(int timeout_ms, uint8_t *response_count)
{
    struct health_monitor_state *state = &g_health_monitor;
    uint8_t buffer[HEALTH_MONITOR_RX_BUFFER_SIZE];
    uint8_t received = 0;
    uint64_t start_time = get_time_ms();

    while (received < HEALTH_MONITOR_EXPECTED_RESPONSES) {
        // Calculate remaining timeout
        uint64_t elapsed = get_time_ms() - start_time;
        if (elapsed >= (uint64_t)timeout_ms) {
            break;  // Timeout
        }
        int remaining = timeout_ms - (int)elapsed;

        // Poll for incoming packets
        struct pollfd pfd;
        pfd.fd = state->rx_socket;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, remaining);
        if (ret < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[HEALTH] Poll error: %s\n", strerror(errno));
            break;
        }

        if (ret == 0) {
            break;  // Timeout
        }

        if (pfd.revents & POLLIN) {
            ssize_t len = recv(state->rx_socket, buffer, sizeof(buffer), 0);
            if (len < 0) {
                if (errno == EINTR || errno == EAGAIN) continue;
                fprintf(stderr, "[HEALTH] Recv error: %s\n", strerror(errno));
                break;
            }

            // Check if this is a health response
            if (is_health_response(buffer, len)) {
                received++;
                char prefix[64];
                snprintf(prefix, sizeof(prefix), "[HEALTH] Response %u/%d",
                         received, HEALTH_MONITOR_EXPECTED_RESPONSES);
                hex_dump(prefix, buffer, len);
            }
            // else: ignore (PRBS or other traffic)
        }
    }

    *response_count = received;
    return 0;
}

// ==========================================
// THREAD FUNCTION
// ==========================================

static void *health_monitor_thread_func(void *arg)
{
    (void)arg;
    struct health_monitor_state *state = &g_health_monitor;

    printf("[HEALTH] Thread started\n");

    while (!(*g_stop_flag) && state->running) {
        uint64_t cycle_start = get_time_ms();

        // 1. Send query
        if (send_health_query() < 0) {
            // Error sending, wait and retry
            usleep(100000);  // 100ms
            continue;
        }

        // Update stats
        pthread_spin_lock(&state->stats_lock);
        state->stats.queries_sent++;
        state->stats.current_sequence = state->sequence;
        pthread_spin_unlock(&state->stats_lock);

        // 2. Receive responses
        uint8_t response_count = 0;
        receive_health_responses(HEALTH_MONITOR_RESPONSE_TIMEOUT_MS, &response_count);

        uint64_t cycle_end = get_time_ms();
        uint64_t cycle_time = cycle_end - cycle_start;

        // 3. Log cycle result
        printf("[HEALTH] Cycle complete: %u/%d responses in %lums\n",
               response_count, HEALTH_MONITOR_EXPECTED_RESPONSES, (unsigned long)cycle_time);

        // 4. Update statistics
        pthread_spin_lock(&state->stats_lock);
        state->stats.responses_received += response_count;
        state->stats.last_cycle_time_ms = cycle_time;
        state->stats.last_response_count = response_count;
        if (response_count < HEALTH_MONITOR_EXPECTED_RESPONSES) {
            state->stats.timeouts++;
        }
        pthread_spin_unlock(&state->stats_lock);

        // 5. Increment sequence (255 -> 1, skip 0)
        if (state->sequence >= 255) {
            state->sequence = 1;
        } else {
            state->sequence++;
        }

        // 6. Wait for remaining time to complete 1 second interval
        uint64_t elapsed = get_time_ms() - cycle_start;
        if (elapsed < HEALTH_MONITOR_QUERY_INTERVAL_MS) {
            usleep((HEALTH_MONITOR_QUERY_INTERVAL_MS - elapsed) * 1000);
        }
    }

    printf("[HEALTH] Thread stopped\n");
    return NULL;
}

// ==========================================
// PUBLIC API
// ==========================================

int init_health_monitor(void)
{
    struct health_monitor_state *state = &g_health_monitor;

    printf("\n=== Initializing Health Monitor ===\n");
    printf("  Interface: %s\n", HEALTH_MONITOR_INTERFACE);
    printf("  Query interval: %d ms\n", HEALTH_MONITOR_QUERY_INTERVAL_MS);
    printf("  Response timeout: %d ms\n", HEALTH_MONITOR_RESPONSE_TIMEOUT_MS);
    printf("  Expected responses: %d\n", HEALTH_MONITOR_EXPECTED_RESPONSES);
    printf("  Response VL_IDX: 0x%04X (%d)\n",
           HEALTH_MONITOR_RESPONSE_VL_IDX, HEALTH_MONITOR_RESPONSE_VL_IDX);

    // Initialize state
    memset(state, 0, sizeof(*state));
    state->tx_socket = -1;
    state->rx_socket = -1;
    state->sequence = HEALTH_MONITOR_SEQ_INIT;
    state->running = false;

    // Copy query template
    memcpy(state->query_packet, health_query_template, HEALTH_MONITOR_QUERY_SIZE);

    // Initialize stats lock
    if (pthread_spin_init(&state->stats_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        fprintf(stderr, "[HEALTH] Failed to init stats lock\n");
        return -1;
    }

    // Get interface index
    state->if_index = get_interface_index(HEALTH_MONITOR_INTERFACE);
    if (state->if_index < 0) {
        fprintf(stderr, "[HEALTH] Interface not found: %s\n", HEALTH_MONITOR_INTERFACE);
        return -1;
    }
    printf("  Interface index: %d\n", state->if_index);

    // Create TX socket
    state->tx_socket = create_raw_socket(HEALTH_MONITOR_INTERFACE, state->if_index);
    if (state->tx_socket < 0) {
        fprintf(stderr, "[HEALTH] Failed to create TX socket\n");
        return -1;
    }
    printf("  TX socket created: fd=%d\n", state->tx_socket);

    // Create RX socket (separate from TX for clean separation)
    state->rx_socket = create_raw_socket(HEALTH_MONITOR_INTERFACE, state->if_index);
    if (state->rx_socket < 0) {
        fprintf(stderr, "[HEALTH] Failed to create RX socket\n");
        close(state->tx_socket);
        state->tx_socket = -1;
        return -1;
    }
    printf("  RX socket created: fd=%d\n", state->rx_socket);

    printf("[HEALTH] Initialization complete\n");
    return 0;
}

int start_health_monitor(volatile bool *stop_flag)
{
    struct health_monitor_state *state = &g_health_monitor;

    if (state->running) {
        fprintf(stderr, "[HEALTH] Already running\n");
        return -1;
    }

    if (state->tx_socket < 0 || state->rx_socket < 0) {
        fprintf(stderr, "[HEALTH] Not initialized\n");
        return -1;
    }

    g_stop_flag = stop_flag;
    state->running = true;

    // Create thread
    if (pthread_create(&state->thread, NULL, health_monitor_thread_func, NULL) != 0) {
        fprintf(stderr, "[HEALTH] Failed to create thread: %s\n", strerror(errno));
        state->running = false;
        return -1;
    }

    printf("[HEALTH] Started\n");
    return 0;
}

void stop_health_monitor(void)
{
    struct health_monitor_state *state = &g_health_monitor;

    if (!state->running) {
        return;
    }

    printf("[HEALTH] Stopping...\n");
    state->running = false;

    // Wait for thread to finish
    pthread_join(state->thread, NULL);

    printf("[HEALTH] Stopped\n");
}

void cleanup_health_monitor(void)
{
    struct health_monitor_state *state = &g_health_monitor;

    // Stop if running
    if (state->running) {
        stop_health_monitor();
    }

    // Close sockets
    if (state->tx_socket >= 0) {
        close(state->tx_socket);
        state->tx_socket = -1;
    }

    if (state->rx_socket >= 0) {
        close(state->rx_socket);
        state->rx_socket = -1;
    }

    // Destroy lock
    pthread_spin_destroy(&state->stats_lock);

    printf("[HEALTH] Cleanup complete\n");
}

void get_health_monitor_stats(struct health_monitor_stats *stats)
{
    struct health_monitor_state *state = &g_health_monitor;

    pthread_spin_lock(&state->stats_lock);
    memcpy(stats, &state->stats, sizeof(*stats));
    pthread_spin_unlock(&state->stats_lock);
}

void print_health_monitor_stats(void)
{
    struct health_monitor_stats stats;
    get_health_monitor_stats(&stats);

    uint64_t expected = stats.queries_sent * HEALTH_MONITOR_EXPECTED_RESPONSES;
    double success_rate = (expected > 0) ?
        (100.0 * stats.responses_received / expected) : 0.0;

    printf("[HEALTH] Stats: Queries=%lu | Responses=%lu/%lu (%.1f%%) | Timeouts=%lu | Seq=0x%02X\n",
           (unsigned long)stats.queries_sent,
           (unsigned long)stats.responses_received,
           (unsigned long)expected,
           success_rate,
           (unsigned long)stats.timeouts,
           stats.current_sequence);
}

bool is_health_monitor_running(void)
{
    return g_health_monitor.running;
}

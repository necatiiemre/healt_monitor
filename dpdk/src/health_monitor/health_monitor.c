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

// ==========================================
// BYTE PARSING FUNCTIONS (Big-Endian)
// ==========================================

static inline uint16_t parse_2byte_be(const uint8_t *data)
{
    return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}

static inline uint32_t parse_4byte_be(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8)  | (uint32_t)data[3];
}

static inline uint64_t parse_6byte_be(const uint8_t *data)
{
    return ((uint64_t)data[0] << 40) | ((uint64_t)data[1] << 32) |
           ((uint64_t)data[2] << 24) | ((uint64_t)data[3] << 16) |
           ((uint64_t)data[4] << 8)  | (uint64_t)data[5];
}

// ==========================================
// DEVICE HEADER PARSING
// ==========================================

static void parse_device_header(const uint8_t *udp_payload, struct health_device_info *dev)
{
    dev->device_id       = parse_2byte_be(udp_payload + DEV_OFF_DEVICE_ID);
    dev->operation_type  = udp_payload[DEV_OFF_OPERATION_TYPE];
    dev->config_type     = udp_payload[DEV_OFF_CONFIG_TYPE];
    dev->frame_length    = parse_2byte_be(udp_payload + DEV_OFF_FRAME_LENGTH);
    dev->status_enable   = udp_payload[DEV_OFF_STATUS_ENABLE];
    dev->tx_total_count  = parse_6byte_be(udp_payload + DEV_OFF_TX_TOTAL_COUNT);
    dev->rx_total_count  = parse_6byte_be(udp_payload + DEV_OFF_RX_TOTAL_COUNT);
    dev->port_count      = udp_payload[DEV_OFF_PORT_COUNT];
    dev->sw_mode         = udp_payload[DEV_OFF_SW_MODE];

    // Firmware version: bytes 48, 49, 50 (last 3 bytes of 6-byte field)
    dev->fw_major = udp_payload[DEV_OFF_FW_VERSION + 3];
    dev->fw_minor = udp_payload[DEV_OFF_FW_VERSION + 4];
    dev->fw_patch = udp_payload[DEV_OFF_FW_VERSION + 5];

    // Embedded ES firmware version: bytes 54, 55, 56
    dev->es_fw_major = udp_payload[DEV_OFF_ES_FW_VERSION + 3];
    dev->es_fw_minor = udp_payload[DEV_OFF_ES_FW_VERSION + 4];
    dev->es_fw_patch = udp_payload[DEV_OFF_ES_FW_VERSION + 5];

    dev->egi_time_sec   = parse_4byte_be(udp_payload + DEV_OFF_EGI_TIME_SEC);
    dev->power_up_time  = parse_4byte_be(udp_payload + DEV_OFF_POWER_UP_TIME);
    dev->instant_time   = parse_4byte_be(udp_payload + DEV_OFF_INSTANT_TIME);
    dev->fpga_temp      = parse_2byte_be(udp_payload + DEV_OFF_FPGA_TEMP);
    dev->fpga_voltage   = parse_2byte_be(udp_payload + DEV_OFF_FPGA_VOLTAGE);
    dev->config_id      = parse_2byte_be(udp_payload + DEV_OFF_CONFIG_ID);
}

// ==========================================
// PORT DATA PARSING
// ==========================================

static void parse_port_data(const uint8_t *port_data, struct health_port_info *port)
{
    port->port_number        = parse_2byte_be(port_data + PORT_OFF_PORT_NUMBER);
    port->bit_status         = port_data[PORT_OFF_BIT_STATUS];
    port->crc_err_count      = parse_6byte_be(port_data + PORT_OFF_CRC_ERR_CNT);
    port->min_vl_frame_err   = parse_6byte_be(port_data + PORT_OFF_MIN_VL_FRAME_ERR);
    port->max_vl_frame_err   = parse_6byte_be(port_data + PORT_OFF_MAX_VL_FRAME_ERR);
    port->traffic_policy_drop = parse_6byte_be(port_data + PORT_OFF_TRAFFIC_POLICY_DROP);
    port->be_count           = parse_6byte_be(port_data + PORT_OFF_BE_COUNT);
    port->tx_count           = parse_6byte_be(port_data + PORT_OFF_TX_COUNT);
    port->rx_count           = parse_6byte_be(port_data + PORT_OFF_RX_COUNT);
    port->vl_source_err      = parse_6byte_be(port_data + PORT_OFF_VL_SOURCE_ERR);
    port->max_delay_err      = parse_6byte_be(port_data + PORT_OFF_MAX_DELAY_ERR);
    port->vlid_drop_count    = parse_6byte_be(port_data + PORT_OFF_VLID_DROP);
    port->undef_mac_count    = parse_6byte_be(port_data + PORT_OFF_UNDEF_MAC);
    port->hp_queue_overflow  = parse_6byte_be(port_data + PORT_OFF_HP_QUEUE_OVERFLOW);
    port->lp_queue_overflow  = parse_6byte_be(port_data + PORT_OFF_LP_QUEUE_OVERFLOW);
    port->be_queue_overflow  = parse_6byte_be(port_data + PORT_OFF_BE_QUEUE_OVERFLOW);
    port->valid = true;
}

// ==========================================
// RESPONSE PARSING
// ==========================================

static struct health_switch_data *determine_switch(const uint8_t *udp_payload,
                                                    bool has_device_header,
                                                    int port_data_offset,
                                                    struct health_cycle_data *cycle)
{
    if (has_device_header) {
        // Use status_enable field from device header
        uint8_t status = udp_payload[DEV_OFF_STATUS_ENABLE];
        if (status == HEALTH_STATUS_MANAGER)
            return &cycle->manager;
        else if (status == HEALTH_STATUS_ASSISTANT)
            return &cycle->assistant;
        else
            return NULL;  // MCU or unknown
    }

    // Mini header: determine by first port number
    uint16_t first_port = parse_2byte_be(udp_payload + port_data_offset + PORT_OFF_PORT_NUMBER);
    if (first_port < HEALTH_ASSISTANT_PORT_COUNT)
        return &cycle->assistant;
    else
        return &cycle->manager;
}

static void health_parse_response(const uint8_t *packet, size_t len, struct health_cycle_data *cycle)
{
    // Get UDP payload pointer
    const uint8_t *udp_payload = packet + HEALTH_UDP_PAYLOAD_OFFSET;

    // Determine packet type by size
    bool has_device_header = false;
    int port_count_in_packet = 0;
    int port_data_offset = 0;

    if (len == HEALTH_PKT_SIZE_WITH_HEADER) {
        // 1187 bytes: Device header + 8 ports
        has_device_header = true;
        port_count_in_packet = 8;
        port_data_offset = HEALTH_DEVICE_HEADER_SIZE;
    } else if (len == HEALTH_PKT_SIZE_8_PORTS) {
        // 1083 bytes: Mini header + 8 ports
        port_count_in_packet = 8;
        port_data_offset = HEALTH_MINI_HEADER_SIZE;
    } else if (len == HEALTH_PKT_SIZE_3_PORTS) {
        // 438 bytes: Mini header + 3 ports
        port_count_in_packet = 3;
        port_data_offset = HEALTH_MINI_HEADER_SIZE;
    } else if (len == HEALTH_PKT_SIZE_MCU) {
        // 84 bytes: MCU data - skip
        return;
    } else {
        // Unknown packet size - skip
        return;
    }

    // Determine which switch this packet belongs to
    struct health_switch_data *sw = determine_switch(udp_payload, has_device_header,
                                                      port_data_offset, cycle);
    if (!sw)
        return;  // MCU or unknown status

    // Parse device header if present (only once per switch)
    if (has_device_header && !sw->device_info_valid) {
        parse_device_header(udp_payload, &sw->device);
        sw->device_info_valid = true;
    }

    // Parse port data
    const uint8_t *port_ptr = udp_payload + port_data_offset;
    for (int i = 0; i < port_count_in_packet; i++) {
        struct health_port_info temp_port;
        memset(&temp_port, 0, sizeof(temp_port));
        parse_port_data(port_ptr, &temp_port);

        // Store in correct slot by port number
        uint16_t pnum = temp_port.port_number;
        if (pnum < HEALTH_MAX_PORTS) {
            sw->ports[pnum] = temp_port;
        }

        port_ptr += HEALTH_PORT_DATA_SIZE;
    }

    sw->responses_received++;
    cycle->total_responses++;
}

// ==========================================
// CONVERSION FUNCTIONS
// ==========================================

static double convert_fpga_voltage(uint16_t raw)
{
    uint16_t integer_part = (raw & 0x7FF8) >> 3;
    uint16_t fractional_part = raw & 0x7;
    double milli_volt = (double)integer_part + (double)fractional_part / 10.0;
    return milli_volt / 1000.0;
}

static double convert_fpga_temperature(uint16_t raw)
{
    uint16_t integer_part = (raw & 0x7FF0) >> 4;
    uint16_t fractional_part = raw & 0xF;
    // String concat: str(integer) + "." + str(fractional)
    // fractional 0-9 -> 1 digit, 10-15 -> 2 digits
    double divisor = (fractional_part >= 10) ? 100.0 : 10.0;
    double kelvin = (double)integer_part + (double)fractional_part / divisor;
    return kelvin - 273.15;
}

// ==========================================
// TABLE PRINTING
// ==========================================

static void health_print_switch_section(const struct health_switch_data *sw,
                                        const char *switch_name,
                                        int port_start, int port_end)
{
    const struct health_device_info *dev = &sw->device;

    // Switch Device Status Header
    printf("[HEALTH] ============ %s Switch ============\n", switch_name);
    if (sw->device_info_valid) {
        printf("[HEALTH] DevID=0x%04X | OpType=0x%02X | CfgType=0x%02X | Mode=0x%02X | Ports=%d\n",
               dev->device_id, dev->operation_type, dev->config_type, dev->sw_mode, dev->port_count);
        printf("[HEALTH] FW=%d.%d.%d | ES_FW=%d.%d.%d | ConfigID=%d\n",
               dev->fw_major, dev->fw_minor, dev->fw_patch,
               dev->es_fw_major, dev->es_fw_minor, dev->es_fw_patch,
               dev->config_id);
        printf("[HEALTH] Temp=%.2fC | Volt=%.4fV | EGI=%us | PowerUp=%us | InstTime=%us\n",
               convert_fpga_temperature(dev->fpga_temp), convert_fpga_voltage(dev->fpga_voltage),
               dev->egi_time_sec, dev->power_up_time, dev->instant_time);
        printf("[HEALTH] TxTotal=%lu | RxTotal=%lu\n",
               (unsigned long)dev->tx_total_count, (unsigned long)dev->rx_total_count);
    } else {
        printf("[HEALTH] Device info not received\n");
    }

    // Port Status Table Header
    printf("[HEALTH] --- %s Ports (%d responses) ---\n", switch_name, sw->responses_received);
    printf("[HEALTH] Port |    TxCnt |    RxCnt | PolDrop | VLDrop | HP_Ovf | LP_Ovf | BE_Ovf |\n");
    printf("[HEALTH] -----|----------|----------|---------|--------|--------|--------|--------|\n");

    // Port Data Rows
    for (int i = port_start; i < port_end; i++) {
        const struct health_port_info *p = &sw->ports[i];
        if (p->valid) {
            printf("[HEALTH] %4d | %8lu | %8lu | %7lu | %6lu | %6lu | %6lu | %6lu |\n",
                   i,
                   (unsigned long)p->tx_count,
                   (unsigned long)p->rx_count,
                   (unsigned long)p->traffic_policy_drop,
                   (unsigned long)p->vlid_drop_count,
                   (unsigned long)p->hp_queue_overflow,
                   (unsigned long)p->lp_queue_overflow,
                   (unsigned long)p->be_queue_overflow);
        } else {
            printf("[HEALTH] %4d |      N/A |      N/A |     N/A |    N/A |    N/A |    N/A |    N/A |\n", i);
        }
    }
}

static void health_print_table(const struct health_cycle_data *cycle)
{
    printf("[HEALTH] ==================== Health Monitor (%d/%d responses) ====================\n",
           cycle->total_responses, HEALTH_MONITOR_EXPECTED_RESPONSES);

    // Manager Switch: ports 16-34
    health_print_switch_section(&cycle->manager, "Manager",
                                HEALTH_MANAGER_PORT_START, HEALTH_MAX_PORTS);

    // Assistant Switch: ports 0-15
    health_print_switch_section(&cycle->assistant, "Assistant",
                                0, HEALTH_ASSISTANT_PORT_COUNT);

    printf("[HEALTH] ========================================================================\n");
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

static int receive_health_responses(int timeout_ms, struct health_cycle_data *cycle)
{
    struct health_monitor_state *state = &g_health_monitor;
    uint8_t buffer[HEALTH_MONITOR_RX_BUFFER_SIZE];
    uint64_t start_time = get_time_ms();

    while (cycle->total_responses < HEALTH_MONITOR_EXPECTED_RESPONSES) {
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

            // Check if this is a health response and parse it
            if (is_health_response(buffer, len)) {
                health_parse_response(buffer, len, cycle);
            }
            // else: ignore non-health packets (PRBS traffic etc.)
        }
    }

    return 0;
}

// ==========================================
// THREAD FUNCTION
// ==========================================

static void *health_monitor_thread_func(void *arg)
{
    (void)arg;
    struct health_monitor_state *state = &g_health_monitor;
    struct health_cycle_data cycle;

    printf("[HEALTH] Thread started\n");

    while (!(*g_stop_flag) && state->running) {
        uint64_t cycle_start = get_time_ms();

        // 1. Reset cycle data
        memset(&cycle, 0, sizeof(cycle));

        // 2. Send query
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

        // 3. Receive and parse responses
        receive_health_responses(HEALTH_MONITOR_RESPONSE_TIMEOUT_MS, &cycle);

        uint64_t cycle_end = get_time_ms();
        uint64_t cycle_time = cycle_end - cycle_start;

        // 4. Print parsed data table
        health_print_table(&cycle);

        // 5. Update statistics
        pthread_spin_lock(&state->stats_lock);
        state->stats.responses_received += cycle.total_responses;
        state->stats.last_cycle_time_ms = cycle_time;
        state->stats.last_response_count = cycle.total_responses;
        if (cycle.total_responses < HEALTH_MONITOR_EXPECTED_RESPONSES) {
            state->stats.timeouts++;
        }
        pthread_spin_unlock(&state->stats_lock);

        // 6. Increment sequence (255 -> 1, skip 0)
        if (state->sequence >= 255) {
            state->sequence = 1;
        } else {
            state->sequence++;
        }

        // 7. Wait for remaining time to complete 1 second interval
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

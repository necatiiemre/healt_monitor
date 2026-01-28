#ifndef HEALTH_TYPES_H
#define HEALTH_TYPES_H

#include <stdint.h>
#include <stdbool.h>

// ==========================================
// PACKET STRUCTURE CONSTANTS
// ==========================================

// Offsets from raw packet start
#define HEALTH_ETH_HEADER_SIZE       14
#define HEALTH_IP_HEADER_SIZE        20
#define HEALTH_UDP_HEADER_SIZE       8
#define HEALTH_UDP_PAYLOAD_OFFSET    (HEALTH_ETH_HEADER_SIZE + HEALTH_IP_HEADER_SIZE + HEALTH_UDP_HEADER_SIZE)  // 42

// Device header size (from UDP payload start)
#define HEALTH_DEVICE_HEADER_SIZE    111

// Mini header size for packets without full device header
#define HEALTH_MINI_HEADER_SIZE      9   // DevID(2) + OpType(1) + CfgType(1) + FrameLen(2) + Reserved(3)

// Port data constants
#define HEALTH_PORT_DATA_SIZE        129
#define HEALTH_MAX_PORTS             35

// Packet sizes for type detection
#define HEALTH_PKT_SIZE_WITH_HEADER  1187  // Device header + 8 ports
#define HEALTH_PKT_SIZE_8_PORTS      1083  // 8 ports (no header)
#define HEALTH_PKT_SIZE_3_PORTS      438   // 3 ports
#define HEALTH_PKT_SIZE_MCU          84    // MCU data (skip)

// ==========================================
// DEVICE HEADER OFFSETS (from UDP payload)
// ==========================================

#define DEV_OFF_DEVICE_ID            0    // 2 bytes
#define DEV_OFF_OPERATION_TYPE       2    // 1 byte
#define DEV_OFF_CONFIG_TYPE          3    // 1 byte
#define DEV_OFF_FRAME_LENGTH         4    // 2 bytes
#define DEV_OFF_STATUS_ENABLE        6    // 1 byte
#define DEV_OFF_TX_TOTAL_COUNT       9    // 6 bytes
#define DEV_OFF_RX_TOTAL_COUNT       15   // 6 bytes
#define DEV_OFF_CBA_TEMP             23   // 4 bytes
#define DEV_OFF_DEV_ID2              34   // 2 bytes
#define DEV_OFF_PORT_COUNT           36   // 1 byte
#define DEV_OFF_TOKEN_BUCKET         37   // 1 byte
#define DEV_OFF_SW_MODE              38   // 1 byte
#define DEV_OFF_MICROCHIP_SEL        39   // 4 bytes
#define DEV_OFF_FW_VERSION           45   // 6 bytes
#define DEV_OFF_ES_FW_VERSION        51   // 6 bytes
#define DEV_OFF_EGI_TIME_SEC         59   // 4 bytes
#define DEV_OFF_HP_FIFO_SIZE         63   // 2 bytes
#define DEV_OFF_LP_FIFO_SIZE         65   // 2 bytes
#define DEV_OFF_BE_FIFO_SIZE         67   // 2 bytes
#define DEV_OFF_POWER_UP_TIME        71   // 4 bytes
#define DEV_OFF_INSTANT_TIME         77   // 4 bytes
#define DEV_OFF_FPGA_TEMP            101  // 2 bytes
#define DEV_OFF_FPGA_VOLTAGE         103  // 2 bytes
#define DEV_OFF_CONFIG_ID            105  // 2 bytes

// ==========================================
// PORT DATA OFFSETS (from port data start)
// ==========================================

#define PORT_OFF_PORT_NUMBER         0    // 2 bytes
#define PORT_OFF_BIT_STATUS          2    // 1 byte
#define PORT_OFF_CRC_ERR_CNT         3    // 6 bytes
#define PORT_OFF_MIN_VL_FRAME_ERR    27   // 6 bytes
#define PORT_OFF_MAX_VL_FRAME_ERR    33   // 6 bytes
#define PORT_OFF_TRAFFIC_POLICY_DROP 45   // 6 bytes
#define PORT_OFF_BE_COUNT            51   // 6 bytes
#define PORT_OFF_TX_COUNT            57   // 6 bytes
#define PORT_OFF_RX_COUNT            63   // 6 bytes
#define PORT_OFF_VL_SOURCE_ERR       69   // 6 bytes
#define PORT_OFF_MAX_DELAY_ERR       75   // 6 bytes
#define PORT_OFF_VLID_DROP           87   // 6 bytes
#define PORT_OFF_UNDEF_MAC           93   // 6 bytes
#define PORT_OFF_HP_QUEUE_OVERFLOW   99   // 6 bytes
#define PORT_OFF_LP_QUEUE_OVERFLOW   105  // 6 bytes
#define PORT_OFF_BE_QUEUE_OVERFLOW   111  // 6 bytes

// ==========================================
// DATA STRUCTURES
// ==========================================

/**
 * @brief Device header information (parsed from response)
 */
struct health_device_info {
    uint16_t device_id;           // Device ID
    uint8_t  operation_type;      // Operation type (e.g., 0x53)
    uint8_t  config_type;         // Config type (e.g., 0x44)
    uint16_t frame_length;        // Monitoring frame length
    uint8_t  status_enable;       // Status enable flags
    uint64_t tx_total_count;      // SW TX total count
    uint64_t rx_total_count;      // SW RX total count
    uint8_t  port_count;          // Number of ports (e.g., 35)
    uint8_t  sw_mode;             // Switch mode
    uint8_t  fw_major;            // Firmware version major
    uint8_t  fw_minor;            // Firmware version minor
    uint8_t  fw_patch;            // Firmware version patch
    uint8_t  es_fw_major;         // Embedded ES firmware major
    uint8_t  es_fw_minor;         // Embedded ES firmware minor
    uint8_t  es_fw_patch;         // Embedded ES firmware patch
    uint32_t egi_time_sec;        // EGI time in seconds
    uint32_t power_up_time;       // FPGA power up time
    uint32_t instant_time;        // Instant time
    uint16_t fpga_temp;           // FPGA temperature (raw)
    uint16_t fpga_voltage;        // FPGA voltage (raw)
    uint16_t config_id;           // Configuration ID
};

/**
 * @brief Port monitoring data (parsed from response)
 */
struct health_port_info {
    uint16_t port_number;         // Port number (0-34)
    uint8_t  bit_status;          // Bit status / stats flags
    uint64_t crc_err_count;       // CRC error count
    uint64_t min_vl_frame_err;    // Min VL frame error count
    uint64_t max_vl_frame_err;    // Max VL frame error count
    uint64_t traffic_policy_drop; // Traffic policy drop count
    uint64_t be_count;            // BE count
    uint64_t tx_count;            // TX count
    uint64_t rx_count;            // RX count
    uint64_t vl_source_err;       // VL source error count
    uint64_t max_delay_err;       // Max delay error count
    uint64_t vlid_drop_count;     // VLID drop count
    uint64_t undef_mac_count;     // Undefined MAC count
    uint64_t hp_queue_overflow;   // High priority queue overflow
    uint64_t lp_queue_overflow;   // Low priority queue overflow
    uint64_t be_queue_overflow;   // Best effort queue overflow
    bool     valid;               // Data received flag
};

/**
 * @brief Complete health cycle data (all responses combined)
 */
struct health_cycle_data {
    struct health_device_info device;              // Device info
    struct health_port_info   ports[HEALTH_MAX_PORTS];  // Port data (0-34)
    uint8_t  responses_received;                   // Number of responses received
    bool     device_info_valid;                    // Device info parsed flag
};

#endif // HEALTH_TYPES_H

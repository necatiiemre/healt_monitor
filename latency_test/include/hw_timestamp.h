/**
 * @file hw_timestamp.h
 * @brief HW Timestamp Latency Test - Hardware Timestamping API
 *
 * SO_TIMESTAMPING ile NIC'lerden PTP hardware timestamp alma
 */

#ifndef HW_TIMESTAMP_H
#define HW_TIMESTAMP_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <linux/net_tstamp.h>

#include "common.h"

// ============================================
// SOCKET TYPES
// ============================================
typedef enum {
    SOCK_TYPE_TX,       // TX için (timestamp geri almak için)
    SOCK_TYPE_RX        // RX için (gelen paketlerin timestamp'i)
} socket_type_t;

// ============================================
// SOCKET INFO STRUCTURE
// ============================================
struct hw_socket {
    int             fd;             // Socket file descriptor
    int             if_index;       // Interface index
    char            if_name[32];    // Interface name
    socket_type_t   type;           // TX veya RX
    bool            hw_ts_enabled;  // HW timestamp aktif mi?
};

// ============================================
// FUNCTION DECLARATIONS
// ============================================

/**
 * Interface'in HW timestamp desteğini kontrol et
 *
 * @param if_name   Interface adı (e.g., "ens1f0np0")
 * @return          true = destekliyor, false = desteklemiyor
 */
bool check_hw_timestamp_support(const char *if_name);

/**
 * Raw socket oluştur ve HW timestamp'i aktif et
 *
 * @param if_name   Interface adı
 * @param type      SOCK_TYPE_TX veya SOCK_TYPE_RX
 * @param sock      Çıktı: socket bilgileri
 * @return          0 = başarılı, <0 = hata kodu
 */
int create_hw_timestamp_socket(const char *if_name, socket_type_t type, struct hw_socket *sock);

/**
 * Socket'i kapat
 *
 * @param sock      Socket bilgileri
 */
void close_hw_timestamp_socket(struct hw_socket *sock);

/**
 * Paket gönder ve TX HW timestamp al
 *
 * @param sock          TX socket
 * @param packet        Paket verisi
 * @param packet_len    Paket uzunluğu
 * @param tx_timestamp  Çıktı: TX HW timestamp (nanoseconds)
 * @return              0 = başarılı, <0 = hata kodu
 */
int send_packet_get_tx_timestamp(struct hw_socket *sock,
                                  const uint8_t *packet,
                                  size_t packet_len,
                                  uint64_t *tx_timestamp);

/**
 * Paket al ve RX HW timestamp al
 *
 * @param sock          RX socket
 * @param packet        Çıktı: paket verisi buffer
 * @param packet_len    Buffer boyutu / Çıktı: alınan paket uzunluğu
 * @param rx_timestamp  Çıktı: RX HW timestamp (nanoseconds)
 * @param timeout_ms    Timeout (milisaniye), 0 = non-blocking
 * @return              0 = başarılı, -1 = timeout, <-1 = hata kodu
 */
int recv_packet_get_rx_timestamp(struct hw_socket *sock,
                                  uint8_t *packet,
                                  size_t *packet_len,
                                  uint64_t *rx_timestamp,
                                  int timeout_ms);

/**
 * Interface'in HW timestamp yeteneklerini yazdır (debug için)
 *
 * @param if_name   Interface adı
 */
void print_hw_timestamp_caps(const char *if_name);

#endif // HW_TIMESTAMP_H

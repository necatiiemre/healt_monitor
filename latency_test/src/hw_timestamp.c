/**
 * @file hw_timestamp.c
 * @brief HW Timestamp Latency Test - Hardware Timestamping Implementation
 *
 * SO_TIMESTAMPING ile NIC'lerden PTP hardware timestamp alma
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <poll.h>

#include "hw_timestamp.h"
#include "common.h"

// ============================================
// INTERNAL HELPERS
// ============================================

/**
 * Interface index al
 */
static int get_interface_index(const char *if_name) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERROR_ERRNO("Failed to create socket for interface index lookup");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        LOG_ERROR_ERRNO("Failed to get interface index for %s", if_name);
        close(sock);
        return -1;
    }

    close(sock);
    return ifr.ifr_ifindex;
}

/**
 * cmsg içinden timestamp çıkar
 */
static bool extract_timestamp_from_cmsg(struct msghdr *msg, uint64_t *timestamp) {
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING) {
            struct timespec *ts = (struct timespec *)CMSG_DATA(cmsg);

            // ts[0] = software timestamp
            // ts[1] = deprecated
            // ts[2] = hardware timestamp (raw)

            // Hardware timestamp öncelikli
            if (ts[2].tv_sec != 0 || ts[2].tv_nsec != 0) {
                *timestamp = timespec_to_ns(&ts[2]);
                LOG_TRACE("Extracted HW timestamp: %lu.%09lu (raw)",
                         ts[2].tv_sec, ts[2].tv_nsec);
                return true;
            }

            // Software timestamp fallback
            if (ts[0].tv_sec != 0 || ts[0].tv_nsec != 0) {
                *timestamp = timespec_to_ns(&ts[0]);
                LOG_WARN("Using SW timestamp (HW not available): %lu.%09lu",
                        ts[0].tv_sec, ts[0].tv_nsec);
                return true;
            }
        }
    }

    return false;
}

// ============================================
// PUBLIC FUNCTIONS
// ============================================

bool check_hw_timestamp_support(const char *if_name) {
    LOG_DEBUG("Checking HW timestamp support for %s", if_name);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERROR_ERRNO("Failed to create socket");
        return false;
    }

    struct ethtool_ts_info ts_info;
    memset(&ts_info, 0, sizeof(ts_info));
    ts_info.cmd = ETHTOOL_GET_TS_INFO;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    ifr.ifr_data = (void *)&ts_info;

    if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
        LOG_ERROR_ERRNO("ETHTOOL_GET_TS_INFO failed for %s", if_name);
        close(sock);
        return false;
    }

    close(sock);

    // Check for hardware TX and RX timestamp support
    bool has_tx_hw = (ts_info.so_timestamping & SOF_TIMESTAMPING_TX_HARDWARE) != 0;
    bool has_rx_hw = (ts_info.so_timestamping & SOF_TIMESTAMPING_RX_HARDWARE) != 0;
    bool has_raw_hw = (ts_info.so_timestamping & SOF_TIMESTAMPING_RAW_HARDWARE) != 0;

    LOG_DEBUG("%s: TX_HW=%d, RX_HW=%d, RAW_HW=%d, phc_index=%d",
             if_name, has_tx_hw, has_rx_hw, has_raw_hw, ts_info.phc_index);

    if (!has_tx_hw || !has_rx_hw) {
        LOG_WARN("%s: HW timestamp not fully supported (TX=%d, RX=%d)",
                if_name, has_tx_hw, has_rx_hw);
        return false;
    }

    LOG_INFO("%s: HW timestamp supported (PHC index: %d)", if_name, ts_info.phc_index);
    return true;
}

void print_hw_timestamp_caps(const char *if_name) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERROR_ERRNO("Failed to create socket");
        return;
    }

    struct ethtool_ts_info ts_info;
    memset(&ts_info, 0, sizeof(ts_info));
    ts_info.cmd = ETHTOOL_GET_TS_INFO;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    ifr.ifr_data = (void *)&ts_info;

    if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
        LOG_ERROR_ERRNO("ETHTOOL_GET_TS_INFO failed for %s", if_name);
        close(sock);
        return;
    }

    close(sock);

    printf("\n=== HW Timestamp Capabilities: %s ===\n", if_name);
    printf("PHC Index: %d\n", ts_info.phc_index);
    printf("SO_TIMESTAMPING flags: 0x%x\n", ts_info.so_timestamping);
    printf("  SOF_TIMESTAMPING_TX_HARDWARE:  %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_TX_HARDWARE) ? "YES" : "NO");
    printf("  SOF_TIMESTAMPING_TX_SOFTWARE:  %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_TX_SOFTWARE) ? "YES" : "NO");
    printf("  SOF_TIMESTAMPING_RX_HARDWARE:  %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_RX_HARDWARE) ? "YES" : "NO");
    printf("  SOF_TIMESTAMPING_RX_SOFTWARE:  %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE) ? "YES" : "NO");
    printf("  SOF_TIMESTAMPING_RAW_HARDWARE: %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_RAW_HARDWARE) ? "YES" : "NO");
    printf("TX types: 0x%x\n", ts_info.tx_types);
    printf("RX filters: 0x%x\n", ts_info.rx_filters);
    printf("=====================================\n\n");
}

int create_hw_timestamp_socket(const char *if_name, socket_type_t type, struct hw_socket *sock) {
    memset(sock, 0, sizeof(*sock));
    strncpy(sock->if_name, if_name, sizeof(sock->if_name) - 1);
    sock->type = type;

    LOG_DEBUG("Creating %s socket for interface %s",
             type == SOCK_TYPE_TX ? "TX" : "RX", if_name);

    // Get interface index
    sock->if_index = get_interface_index(if_name);
    if (sock->if_index < 0) {
        return -1;
    }

    // Create raw socket
    sock->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock->fd < 0) {
        LOG_ERROR_ERRNO("Failed to create raw socket for %s", if_name);
        return -2;
    }

    // Bind to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = sock->if_index;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_ERROR_ERRNO("Failed to bind socket to %s", if_name);
        close(sock->fd);
        sock->fd = -1;
        return -3;
    }

    // Enable promiscuous mode for RX socket (needed for multicast packets)
    if (type == SOCK_TYPE_RX) {
        struct packet_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = sock->if_index;
        mreq.mr_type = PACKET_MR_PROMISC;

        if (setsockopt(sock->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            LOG_WARN("Failed to enable promiscuous mode on %s: %s (continuing anyway)",
                    if_name, strerror(errno));
        } else {
            LOG_DEBUG("Promiscuous mode enabled on %s", if_name);
        }
    }

    // Enable hardware timestamping
    int ts_flags = SOF_TIMESTAMPING_RAW_HARDWARE;

    if (type == SOCK_TYPE_TX) {
        ts_flags |= SOF_TIMESTAMPING_TX_HARDWARE;
        ts_flags |= SOF_TIMESTAMPING_OPT_TSONLY;  // Timestamp only, no packet echo
    } else {
        ts_flags |= SOF_TIMESTAMPING_RX_HARDWARE;
    }

    if (setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMPING, &ts_flags, sizeof(ts_flags)) < 0) {
        LOG_ERROR_ERRNO("Failed to enable SO_TIMESTAMPING on %s", if_name);
        close(sock->fd);
        sock->fd = -1;
        return -4;
    }

    // Enable hardware timestamping on the NIC (SIOCSHWTSTAMP)
    struct ifreq ifr;
    struct hwtstamp_config hwts_config;

    memset(&ifr, 0, sizeof(ifr));
    memset(&hwts_config, 0, sizeof(hwts_config));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    hwts_config.tx_type = (type == SOCK_TYPE_TX) ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
    hwts_config.rx_filter = (type == SOCK_TYPE_RX) ? HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE;

    ifr.ifr_data = (void *)&hwts_config;

    if (ioctl(sock->fd, SIOCSHWTSTAMP, &ifr) < 0) {
        // Some drivers don't support SIOCSHWTSTAMP, try to continue anyway
        LOG_WARN("SIOCSHWTSTAMP failed for %s (may still work): %s",
                if_name, strerror(errno));
    } else {
        LOG_DEBUG("SIOCSHWTSTAMP configured for %s: tx_type=%d, rx_filter=%d",
                 if_name, hwts_config.tx_type, hwts_config.rx_filter);
    }

    sock->hw_ts_enabled = true;

    LOG_INFO("Created %s socket for %s (fd=%d, if_index=%d)",
            type == SOCK_TYPE_TX ? "TX" : "RX", if_name, sock->fd, sock->if_index);

    return 0;
}

void close_hw_timestamp_socket(struct hw_socket *sock) {
    if (sock && sock->fd >= 0) {
        LOG_DEBUG("Closing socket for %s (fd=%d)", sock->if_name, sock->fd);
        close(sock->fd);
        sock->fd = -1;
    }
}

int send_packet_get_tx_timestamp(struct hw_socket *sock,
                                  const uint8_t *packet,
                                  size_t packet_len,
                                  uint64_t *tx_timestamp) {
    *tx_timestamp = 0;

    LOG_TRACE("Sending packet on %s (%zu bytes)", sock->if_name, packet_len);
    hex_dump("TX Packet", packet, MIN(packet_len, 64));

    // Send the packet
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = sock->if_index;
    sll.sll_halen = ETH_ALEN;
    memcpy(sll.sll_addr, packet, ETH_ALEN);  // Destination MAC

    ssize_t sent = sendto(sock->fd, packet, packet_len, 0,
                          (struct sockaddr *)&sll, sizeof(sll));

    if (sent < 0) {
        LOG_ERROR_ERRNO("sendto() failed on %s", sock->if_name);
        return -1;
    }

    if ((size_t)sent != packet_len) {
        LOG_WARN("Partial send on %s: %zd/%zu bytes", sock->if_name, sent, packet_len);
    }

    LOG_TRACE("Sent %zd bytes, waiting for TX timestamp...", sent);

    // Wait for TX timestamp from error queue
    struct pollfd pfd;
    pfd.fd = sock->fd;
    pfd.events = POLLERR;  // TX timestamp comes via error queue

    int poll_ret = poll(&pfd, 1, 100);  // 100ms timeout for TX timestamp

    if (poll_ret < 0) {
        if (errno == EINTR) {
            // Interrupted by signal, return special code
            LOG_DEBUG("poll() interrupted by signal waiting for TX timestamp");
            return -10;
        }
        LOG_ERROR_ERRNO("poll() failed waiting for TX timestamp");
        return -2;
    }

    if (poll_ret == 0) {
        LOG_WARN("Timeout waiting for TX timestamp on %s", sock->if_name);
        return -3;
    }

    // Read TX timestamp from error queue
    uint8_t ctrl_buf[1024];
    struct iovec iov;
    uint8_t dummy_buf[1];
    iov.iov_base = dummy_buf;
    iov.iov_len = sizeof(dummy_buf);

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl_buf;
    msg.msg_controllen = sizeof(ctrl_buf);

    ssize_t recv_len = recvmsg(sock->fd, &msg, MSG_ERRQUEUE);

    if (recv_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            LOG_WARN("No TX timestamp available (EAGAIN) on %s", sock->if_name);
            return -4;
        }
        LOG_ERROR_ERRNO("recvmsg(MSG_ERRQUEUE) failed on %s", sock->if_name);
        return -5;
    }

    // Extract timestamp from control message
    if (!extract_timestamp_from_cmsg(&msg, tx_timestamp)) {
        LOG_WARN("No timestamp in TX error queue message on %s", sock->if_name);
        return -6;
    }

    LOG_DEBUG("TX timestamp for %s: %lu ns", sock->if_name, *tx_timestamp);

    return 0;
}

int recv_packet_get_rx_timestamp(struct hw_socket *sock,
                                  uint8_t *packet,
                                  size_t *packet_len,
                                  uint64_t *rx_timestamp,
                                  int timeout_ms) {
    *rx_timestamp = 0;

    // Poll for incoming packet
    struct pollfd pfd;
    pfd.fd = sock->fd;
    pfd.events = POLLIN;

    LOG_TRACE("Waiting for RX packet on %s (timeout=%d ms)", sock->if_name, timeout_ms);

    int poll_ret = poll(&pfd, 1, timeout_ms);

    if (poll_ret < 0) {
        if (errno == EINTR) {
            // Interrupted by signal (Ctrl+C), return special code
            LOG_DEBUG("poll() interrupted by signal on %s", sock->if_name);
            return -10;  // Interrupted
        }
        LOG_ERROR_ERRNO("poll() failed on %s", sock->if_name);
        return -2;
    }

    if (poll_ret == 0) {
        LOG_TRACE("RX timeout on %s", sock->if_name);
        return -1;  // Timeout
    }

    // Receive packet with timestamp
    uint8_t ctrl_buf[1024];
    struct iovec iov;
    iov.iov_base = packet;
    iov.iov_len = *packet_len;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl_buf;
    msg.msg_controllen = sizeof(ctrl_buf);

    ssize_t recv_len = recvmsg(sock->fd, &msg, 0);

    if (recv_len < 0) {
        LOG_ERROR_ERRNO("recvmsg() failed on %s", sock->if_name);
        return -3;
    }

    *packet_len = (size_t)recv_len;

    LOG_TRACE("Received %zd bytes on %s", recv_len, sock->if_name);
    hex_dump("RX Packet", packet, MIN(recv_len, 64));

    // Extract timestamp
    if (!extract_timestamp_from_cmsg(&msg, rx_timestamp)) {
        LOG_WARN("No RX timestamp in message on %s", sock->if_name);
        // Packet received even without timestamp, continue
    } else {
        LOG_DEBUG("RX timestamp for %s: %lu ns", sock->if_name, *rx_timestamp);
    }

    return 0;
}

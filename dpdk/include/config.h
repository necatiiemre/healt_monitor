#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#define stringify(x) #x

// ==========================================
// LATENCY TEST CONFIGURATION
// ==========================================
// Etkinleştirildiğinde:
// - Her VLAN'dan 1 paket gönderilir (ilk VL-ID kullanılır)
// - TX timestamp payload'a yazılır
// - RX'te latency hesaplanır ve gösterilir
// - 5 saniye timeout
// - Test sonrası normal moda geçilir
// - IMIX devre dışı, MAX paket boyutu (1518) kullanılır

#ifndef LATENCY_TEST_ENABLED
#define LATENCY_TEST_ENABLED 1
#endif

#define LATENCY_TEST_TIMEOUT_SEC 5    // Paket bekleme timeout (saniye)
#define LATENCY_TEST_PACKET_SIZE 1518 // Test paketi boyutu (MAX)

// ==========================================
// IMIX (Internet Mix) CONFIGURATION
// ==========================================
// Özel IMIX profili: Farklı paket boyutlarının dağılımı
// Toplam oran: %10 + %10 + %10 + %10 + %30 + %30 = %100
//
// 10 paketlik döngüde:
//   1x 100 byte  (%10)
//   1x 200 byte  (%10)
//   1x 400 byte  (%10)
//   1x 800 byte  (%10)
//   3x 1200 byte (%30)
//   3x 1518 byte (%30)  - MTU sınırı
//
// Ortalama paket boyutu: ~964 byte

#define IMIX_ENABLED 1

// IMIX boyut seviyeleri (Ethernet frame boyutu, VLAN dahil)
#define IMIX_SIZE_1 100 // En küçük
#define IMIX_SIZE_2 200
#define IMIX_SIZE_3 400
#define IMIX_SIZE_4 800
#define IMIX_SIZE_5 1200
#define IMIX_SIZE_6 1518 // MTU sınırı (VLAN ile 1522, ama 1518 güvenli)

// IMIX pattern boyutu (10 paketlik döngü)
#define IMIX_PATTERN_SIZE 10

// IMIX ortalama paket boyutu (rate limiting için)
// (100 + 200 + 400 + 800 + 1200*3 + 1518*3) / 10 = 964.4
#define IMIX_AVG_PACKET_SIZE 964

// IMIX minimum ve maksimum boyutlar
#define IMIX_MIN_PACKET_SIZE IMIX_SIZE_1
#define IMIX_MAX_PACKET_SIZE IMIX_SIZE_6

// IMIX pattern dizisi (statik tanım - her worker kendi offset'i ile kullanır)
// Sıra: 100, 200, 400, 800, 1200, 1200, 1200, 1518, 1518, 1518
#define IMIX_PATTERN_INIT {                             \
    IMIX_SIZE_1, IMIX_SIZE_2, IMIX_SIZE_3, IMIX_SIZE_4, \
    IMIX_SIZE_5, IMIX_SIZE_5, IMIX_SIZE_5,              \
    IMIX_SIZE_6, IMIX_SIZE_6, IMIX_SIZE_6}

// ==========================================
// RAW SOCKET PORT CONFIGURATION (Non-DPDK)
// ==========================================
// Bu portlar DPDK desteklemeyen NIC'ler için raw socket + zero copy kullanır.
// Multi-target: Tek port birden fazla hedefe farklı hızlarda gönderebilir.
//
// Port 12 (1G bakır): 5 hedefe gönderim (toplam 960 Mbps)
//   - Hedef 0: Port 13'e  80 Mbps, VL-ID 4099-4226 (128)
//   - Hedef 1: Port 5'e  220 Mbps, VL-ID 4227-4738 (512)
//   - Hedef 2: Port 4'e  220 Mbps, VL-ID 4739-5250 (512)
//   - Hedef 3: Port 7'e  220 Mbps, VL-ID 5251-5762 (512)
//   - Hedef 4: Port 6'e  220 Mbps, VL-ID 5763-6274 (512)
//
// Port 13 (100M bakır): 1 hedefe gönderim (80 Mbps)
//   - Hedef 0: Port 12'e 80 Mbps, VL-ID 6275-6306 (32)

#define MAX_RAW_SOCKET_PORTS 2
#define RAW_SOCKET_PORT_ID_START 12
#define MAX_RAW_TARGETS 8 // Maksimum hedef sayısı per port

// Port 12 configuration (1G copper)
#define RAW_SOCKET_PORT_12_PCI "01:00.0"
#define RAW_SOCKET_PORT_12_IFACE "eno12399"
#define RAW_SOCKET_PORT_12_IS_1G true

// Port 13 configuration (100M copper)
#define RAW_SOCKET_PORT_13_PCI "01:00.1"
#define RAW_SOCKET_PORT_13_IFACE "eno12409"
#define RAW_SOCKET_PORT_13_IS_1G false

// ==========================================
// MULTI-TARGET CONFIGURATION
// ==========================================

// TX Target: Bir portun gönderim yaptığı hedef
struct raw_tx_target_config
{
  uint16_t target_id;   // Hedef ID (0, 1, 2, ...)
  uint16_t dest_port;   // Hedef port numarası (13, 5, 4, 7, 6, 12)
  uint32_t rate_mbps;   // Bu hedef için hız (Mbps)
  uint16_t vl_id_start; // VL-ID başlangıç
  uint16_t vl_id_count; // VL-ID sayısı
};

// RX Source: Bir portun kabul ettiği kaynak (doğrulama için)
struct raw_rx_source_config
{
  uint16_t source_port; // Kaynak port numarası
  uint16_t vl_id_start; // Beklenen VL-ID başlangıç
  uint16_t vl_id_count; // Beklenen VL-ID sayısı
};

// Port 12 TX Targets (4 hedef, toplam 900 Mbps)
// Port 13'e gönderim kaldırıldı, sadece DPDK portlarına (2,3,4,5) gönderim
// Hız 205 -> 225 Mbps'e yükseltildi
#define PORT_12_TX_TARGET_COUNT 4
#define PORT_12_TX_TARGETS_INIT {                                                               \
    {.target_id = 0, .dest_port = 2, .rate_mbps = 240, .vl_id_start = 4259, .vl_id_count = 32}, \
    {.target_id = 1, .dest_port = 3, .rate_mbps = 240, .vl_id_start = 4227, .vl_id_count = 32}, \
    {.target_id = 2, .dest_port = 4, .rate_mbps = 240, .vl_id_start = 4195, .vl_id_count = 32}, \
    {.target_id = 3, .dest_port = 5, .rate_mbps = 240, .vl_id_start = 4163, .vl_id_count = 32}, \
}

// Port 12 RX Sources (Port 13'ten gelen paketler kaldırıldı)
// Artık sadece DPDK External TX (Port 2,3,4,5) paketleri alınıyor
#define PORT_12_RX_SOURCE_COUNT 0
#define PORT_12_RX_SOURCES_INIT \
  {                             \
  }

// Port 13 TX Targets (2 hedef, toplam ~90 Mbps)
// Port 12'ye gönderim kaldırıldı, DPDK portlarına (7, 1) gönderim eklendi
#define PORT_13_TX_TARGET_COUNT 2
#define PORT_13_TX_TARGETS_INIT {                                                              \
    {.target_id = 0, .dest_port = 7, .rate_mbps = 45, .vl_id_start = 4131, .vl_id_count = 16}, \
    {.target_id = 1, .dest_port = 1, .rate_mbps = 45, .vl_id_start = 4147, .vl_id_count = 16}, \
}

// Port 13 RX Sources (Port 12'den gelen paketler kaldırıldı)
// Port 13 artık sadece TX yapıyor (Port 7 ve Port 1'e)
#define PORT_13_RX_SOURCE_COUNT 0
#define PORT_13_RX_SOURCES_INIT \
  {                             \
  }

// Raw socket port configuration structure
struct raw_socket_port_config
{
  uint16_t port_id;           // Global port ID (12 or 13)
  const char *pci_addr;       // PCI address (for identification)
  const char *interface_name; // Kernel interface name
  bool is_1g_port;            // true for 1G, false for 100M

  // TX targets
  uint16_t tx_target_count;
  struct raw_tx_target_config tx_targets[MAX_RAW_TARGETS];

  // RX sources (for validation)
  uint16_t rx_source_count;
  struct raw_rx_source_config rx_sources[MAX_RAW_TARGETS];
};

// Helper macro for tx_targets initialization
#define INIT_TX_TARGETS_12 PORT_12_TX_TARGETS_INIT
#define INIT_TX_TARGETS_13 PORT_13_TX_TARGETS_INIT
#define INIT_RX_SOURCES_12 PORT_12_RX_SOURCES_INIT
#define INIT_RX_SOURCES_13 PORT_13_RX_SOURCES_INIT

// Raw socket port configurations
#define RAW_SOCKET_PORTS_CONFIG_INIT                   \
  {                                                    \
    /* Port 12: 1G bakir, 5 TX hedef, 1 RX kaynak */   \
    {.port_id = 12,                                    \
     .pci_addr = RAW_SOCKET_PORT_12_PCI,               \
     .interface_name = RAW_SOCKET_PORT_12_IFACE,       \
     .is_1g_port = RAW_SOCKET_PORT_12_IS_1G,           \
     .tx_target_count = PORT_12_TX_TARGET_COUNT,       \
     .tx_targets = INIT_TX_TARGETS_12,                 \
     .rx_source_count = PORT_12_RX_SOURCE_COUNT,       \
     .rx_sources = INIT_RX_SOURCES_12},                \
    /* Port 13: 100M bakir, 1 TX hedef, 1 RX kaynak */ \
    {                                                  \
      .port_id = 13,                                   \
      .pci_addr = RAW_SOCKET_PORT_13_PCI,              \
      .interface_name = RAW_SOCKET_PORT_13_IFACE,      \
      .is_1g_port = RAW_SOCKET_PORT_13_IS_1G,          \
      .tx_target_count = PORT_13_TX_TARGET_COUNT,      \
      .tx_targets = INIT_TX_TARGETS_13,                \
      .rx_source_count = PORT_13_RX_SOURCE_COUNT,      \
      .rx_sources = INIT_RX_SOURCES_13                 \
    }                                                  \
  }

// ==========================================
// VLAN & VL-ID MAPPING (PORT-AWARE)
// ==========================================
//
// Her port için tx_vl_ids ve rx_vl_ids FARKLI olabilir!
// Aralıklar 128 adet VL-ID içerir ve [start, start+128) şeklinde tanımlanır.
//
// Örnek (Port 0):
//   tx_vl_ids = {1027, 1155, 1283, 1411}
//   Queue 0 → VL ID [1027, 1155)  → 1027..1154 (128 adet)
//   Queue 1 → VL ID [1155, 1283)  → 1155..1282 (128 adet)
//   Queue 2 → VL ID [1283, 1411)  → 1283..1410 (128 adet)
//   Queue 3 → VL ID [1411, 1539)  → 1411..1538 (128 adet)
//
// Örnek (Port 2 - eski varsayılan değerler):
//   tx_vl_ids = {3, 131, 259, 387}
//   Queue 0 → VL ID [  3, 131)  → 3..130   (128 adet)
//   Queue 1 → VL ID [131, 259)  → 131..258 (128 adet)
//   Queue 2 → VL ID [259, 387)  → 259..386 (128 adet)
//   Queue 3 → VL ID [387, 515)  → 387..514 (128 adet)
//
// Not: VLAN header'daki VLAN ID (802.1Q tag) ile VL-ID farklı kavramlardır.
// VL-ID, paketin DST MAC ve DST IP son 2 baytına yazılır.
// VLAN ID ise .tx_vlans / .rx_vlans dizilerinden gelir.
//
// Paket oluştururken:
//   DST MAC: 03:00:00:00:VV:VV  (VV:VL-ID'nin 16-bit'i)
//   DST IP : 224.224.VV.VV      (VV:VL-ID'nin 16-bit'i)
//
// NOT: g_vlid_ranges artık KULLANILMIYOR! Sadece referans için tutuluyor.
// Gerçek VL-ID aralıkları port_vlans[].tx_vl_ids ve rx_vl_ids'den okunuyor.

typedef struct
{
  uint16_t start; // inclusive
  uint16_t end;   // exclusive
} vlid_range_t;

// DEPRECATED: Bu sabit değerler artık kullanılmıyor!
// Her port için config'deki tx_vl_ids/rx_vl_ids değerleri kullanılıyor.
#define VLID_RANGE_COUNT 4
static const vlid_range_t g_vlid_ranges[VLID_RANGE_COUNT] = {
    {3, 131},   // Queue 0 (sadece referans)
    {131, 259}, // Queue 1 (sadece referans)
    {259, 387}, // Queue 2 (sadece referans)
    {387, 515}  // Queue 3 (sadece referans)
};

// DEPRECATED: Bu makrolar artık kullanılmıyor!
// tx_rx_manager.c içindeki port-aware fonksiyonları kullanın.
#define VL_RANGE_START(q) (g_vlid_ranges[(q)].start)
#define VL_RANGE_END(q) (g_vlid_ranges[(q)].end)
#define VL_RANGE_SIZE(q) (uint16_t)(VL_RANGE_END(q) - VL_RANGE_START(q)) // 128

// ==========================================
/* VLAN CONFIGURATION */
// ==========================================
#define MAX_TX_VLANS_PER_PORT 32
#define MAX_RX_VLANS_PER_PORT 32
#define MAX_PORTS_CONFIG 16

struct port_vlan_config
{
  uint16_t tx_vlans[MAX_TX_VLANS_PER_PORT]; // VLAN header tags
  uint16_t tx_vlan_count;
  uint16_t rx_vlans[MAX_RX_VLANS_PER_PORT]; // VLAN header tags
  uint16_t rx_vlan_count;

  // Init için başlangıç VL-ID'leri (queue index ile eşleşir)
  // Dinamik kullanımda bu VL aralıklarının içinde döneceksin.
  uint16_t tx_vl_ids[MAX_TX_VLANS_PER_PORT]; // {3,131,259,387}
  uint16_t rx_vl_ids[MAX_RX_VLANS_PER_PORT]; // {3,131,259,387}
};

// Port bazlı VLAN/VL-ID şablonu (queue index ↔ VL aralığı başlangıcı eşleşir)
#define PORT_VLAN_CONFIG_INIT                                                                                                                                                                               \
  {                                                                                                                                                                                                         \
    /* Port 0 */                                                                                                                                                                                            \
    {.tx_vlans = {105, 106, 107, 108}, .tx_vlan_count = 4, .rx_vlans = {253, 254, 255, 256}, .rx_vlan_count = 4, .tx_vl_ids = {1027, 1155, 1283, 1411}, .rx_vl_ids = {3, 131, 259, 387}},     /* Port 1 */  \
        {.tx_vlans = {109, 110, 111, 112}, .tx_vlan_count = 4, .rx_vlans = {249, 250, 251, 252}, .rx_vlan_count = 4, .tx_vl_ids = {1539, 1667, 1795, 1923}, .rx_vl_ids = {3, 131, 259, 387}}, /* Port 2 */  \
        {.tx_vlans = {97, 98, 99, 100}, .tx_vlan_count = 4, .rx_vlans = {245, 246, 247, 248}, .rx_vlan_count = 4, .tx_vl_ids = {3, 131, 259, 387}, .rx_vl_ids = {3, 131, 259, 387}},          /* Port 3 */  \
        {.tx_vlans = {101, 102, 103, 104}, .tx_vlan_count = 4, .rx_vlans = {241, 242, 243, 244}, .rx_vlan_count = 4, .tx_vl_ids = {515, 643, 771, 899}, .rx_vl_ids = {3, 131, 259, 387}},     /* Port 4 */  \
        {.tx_vlans = {113, 114, 115, 116}, .tx_vlan_count = 4, .rx_vlans = {229, 230, 231, 232}, .rx_vlan_count = 4, .tx_vl_ids = {2051, 2179, 2307, 2435}, .rx_vl_ids = {3, 131, 259, 387}}, /* Port 5 */  \
        {.tx_vlans = {117, 118, 119, 120}, .tx_vlan_count = 4, .rx_vlans = {225, 226, 227, 228}, .rx_vlan_count = 4, .tx_vl_ids = {2563, 2691, 2819, 2947}, .rx_vl_ids = {3, 131, 259, 387}}, /* Port 6 */  \
        {.tx_vlans = {121, 122, 123, 124}, .tx_vlan_count = 4, .rx_vlans = {237, 238, 239, 240}, .rx_vlan_count = 4, .tx_vl_ids = {3075, 3203, 3331, 3459}, .rx_vl_ids = {3, 131, 259, 387}}, /* Port 7 */  \
        {.tx_vlans = {125, 126, 127, 128}, .tx_vlan_count = 4, .rx_vlans = {233, 234, 235, 236}, .rx_vlan_count = 4, .tx_vl_ids = {3587, 3715, 3843, 3971}, .rx_vl_ids = {3, 131, 259, 387}}, /* Port 8 */  \
        {.tx_vlans = {129, 130, 131, 132}, .tx_vlan_count = 4, .rx_vlans = {133, 134, 135, 136}, .rx_vlan_count = 4, .tx_vl_ids = {3, 131, 259, 387}, .rx_vl_ids = {3, 131, 259, 387}},       /* Port 9 */  \
        {.tx_vlans = {129, 130, 131, 132}, .tx_vlan_count = 4, .rx_vlans = {133, 134, 135, 136}, .rx_vlan_count = 4, .tx_vl_ids = {3, 131, 259, 387}, .rx_vl_ids = {3, 131, 259, 387}},       /* Port 10 */ \
        {.tx_vlans = {137, 138, 139, 140}, .tx_vlan_count = 4, .rx_vlans = {141, 142, 143, 144}, .rx_vlan_count = 4, .tx_vl_ids = {3, 131, 259, 387}, .rx_vl_ids = {3, 131, 259, 387}},                     \
    /* Port 11 */                                                                                                                                                                                           \
    {                                                                                                                                                                                                       \
      .tx_vlans = {137, 138, 139, 140}, .tx_vlan_count = 4,                                                                                                                                                 \
      .rx_vlans = {141, 142, 143, 144}, .rx_vlan_count = 4,                                                                                                                                                 \
      .tx_vl_ids = {3, 131, 259, 387},                                                                                                                                                                      \
      .rx_vl_ids = {3, 131, 259, 387}                                                                                                                                                                       \
    }                                                                                                                                                                                                       \
  }

// ==========================================
// TX/RX CORE CONFIGURATION
// ==========================================
// (Makefile ile override edilebilir)
#ifndef NUM_TX_CORES
#define NUM_TX_CORES 2
#endif

#ifndef NUM_RX_CORES
#define NUM_RX_CORES 4
#endif

// ==========================================
// PORT-BASED RATE LIMITING
// ==========================================
// Port 0, 1, 6, 7, 8: Hızlı (Port 12'ye bağlı değil)
// Port 2, 3, 4, 5: Yavaş (Port 12'ye bağlı, external TX yapıyorlar)

#ifndef TARGET_GBPS_FAST
#define TARGET_GBPS_FAST 3.6
#endif

#ifndef TARGET_GBPS_MID
#define TARGET_GBPS_MID 3.4
#endif

#ifndef TARGET_GBPS_SLOW
#define TARGET_GBPS_SLOW 3.4
#endif

// DPDK-DPDK portları (hızlı)
#define IS_FAST_PORT(port_id) ((port_id) == 1 || (port_id) == 7 || (port_id) == 8)

// Port 12 ile bağlı DPDK portları (orta hız)
#define IS_MID_PORT(port_id) ((port_id) == 2 || (port_id) == 3 || \
                              (port_id) == 4 || (port_id) == 5)

// Port 13 ile bağlı DPDK portları (yavaş)
#define IS_SLOW_PORT(port_id) ((port_id) == 0 || (port_id) == 6)

// Port bazlı hedef rate (Gbps)
// FAST: DPDK-DPDK portları (1,7,8)
// MID: Port 12 ile bağlı portlar (2,3,4,5)
// SLOW: Port 13 ile bağlı portlar (0,6)
#define GET_PORT_TARGET_GBPS(port_id)                                                \
  (IS_FAST_PORT(port_id) ? TARGET_GBPS_FAST : IS_MID_PORT(port_id) ? TARGET_GBPS_MID \
                                                                   : TARGET_GBPS_SLOW)

#ifndef RATE_LIMITER_ENABLED
#define RATE_LIMITER_ENABLED 1
#endif

// Kuyruk sayıları core sayılarına eşittir
#define NUM_TX_QUEUES_PER_PORT NUM_TX_CORES
#define NUM_RX_QUEUES_PER_PORT NUM_RX_CORES

// ==========================================
// PACKET CONFIGURATION (Sabit alanlar)
// ==========================================
#define DEFAULT_TTL 1
#define DEFAULT_TOS 0
#define DEFAULT_VLAN_PRIORITY 0

// MAC/IP şablonları
#define DEFAULT_SRC_MAC "02:00:00:00:00:20"  // Sabit kaynak MAC
#define DEFAULT_DST_MAC_PREFIX "03:00:00:00" // Son 2 bayt = VL-ID

#define DEFAULT_SRC_IP "10.0.0.0"       // Sabit kaynak IP
#define DEFAULT_DST_IP_PREFIX "224.224" // Son 2 bayt = VL-ID

// UDP portları
#define DEFAULT_SRC_PORT 100
#define DEFAULT_DST_PORT 100

// ==========================================
// STATISTICS CONFIGURATION
// ==========================================
#define STATS_INTERVAL_SEC 1 // N saniyede bir istatistik yaz

// ==========================================
// DPDK EXTERNAL TX CONFIGURATION
// ==========================================
// Bu sistem mevcut DPDK TX'ten BAĞIMSIZ çalışır.
// DPDK Port 0,1,2,3 → Switch → Port 12 (raw socket) yolunu kullanır.
// Her port 4 queue ile 4 farklı VLAN/VL-ID kombinasyonu gönderir.
//
// Akış:
//   DPDK Port TX → Physical wire → Switch → Port 12 NIC → Raw socket RX
//
// Port 12 (raw socket) bu paketleri alıp PRBS ve sequence doğrulaması yapar.

#define DPDK_EXT_TX_ENABLED 1
#define DPDK_EXT_TX_PORT_COUNT 6 // Port 2,3,4,5 → Port 12 | Port 0,6 → Port 13
#define DPDK_EXT_TX_QUEUES_PER_PORT 4

// External TX target configuration
struct dpdk_ext_tx_target
{
  uint16_t queue_id;    // Queue index (0-3)
  uint16_t vlan_id;     // VLAN tag
  uint16_t vl_id_start; // VL-ID başlangıç
  uint16_t vl_id_count; // VL-ID sayısı (32)
  uint32_t rate_mbps;   // Hedef hız (Mbps)
};

// External TX port configuration
struct dpdk_ext_tx_port_config
{
  uint16_t port_id;      // DPDK port ID
  uint16_t dest_port;    // Hedef raw socket port (12 veya 13)
  uint16_t target_count; // Hedef sayısı (4)
  struct dpdk_ext_tx_target targets[DPDK_EXT_TX_QUEUES_PER_PORT];
};

// Port 2: VLAN 97-100, VL-ID 4291-4322
// NOTE: Total external TX must not exceed Port 12's 1G capacity
// 4 ports × 220 Mbps = 880 Mbps total (within 1G limit)
#define DPDK_EXT_TX_PORT_2_TARGETS {                                                          \
    {.queue_id = 0, .vlan_id = 97, .vl_id_start = 4291, .vl_id_count = 8, .rate_mbps = 240},  \
    {.queue_id = 1, .vlan_id = 98, .vl_id_start = 4299, .vl_id_count = 8, .rate_mbps = 240},  \
    {.queue_id = 2, .vlan_id = 99, .vl_id_start = 4307, .vl_id_count = 8, .rate_mbps = 240},  \
    {.queue_id = 3, .vlan_id = 100, .vl_id_start = 4315, .vl_id_count = 8, .rate_mbps = 240}, \
}

// Port 3: VLAN 101-104, VL-ID 4323-4354 (8 per queue, no overlap)
#define DPDK_EXT_TX_PORT_3_TARGETS {                                                          \
    {.queue_id = 0, .vlan_id = 101, .vl_id_start = 4323, .vl_id_count = 8, .rate_mbps = 240}, \
    {.queue_id = 1, .vlan_id = 102, .vl_id_start = 4331, .vl_id_count = 8, .rate_mbps = 240}, \
    {.queue_id = 2, .vlan_id = 103, .vl_id_start = 4339, .vl_id_count = 8, .rate_mbps = 240}, \
    {.queue_id = 3, .vlan_id = 104, .vl_id_start = 4347, .vl_id_count = 8, .rate_mbps = 240}, \
}

// Port 0: VLAN 105-108, VL-ID 4355-4386
#define DPDK_EXT_TX_PORT_4_TARGETS {                                                          \
    {.queue_id = 0, .vlan_id = 113, .vl_id_start = 4355, .vl_id_count = 8, .rate_mbps = 240}, \
    {.queue_id = 1, .vlan_id = 114, .vl_id_start = 4363, .vl_id_count = 8, .rate_mbps = 240}, \
    {.queue_id = 2, .vlan_id = 115, .vl_id_start = 4371, .vl_id_count = 8, .rate_mbps = 240}, \
    {.queue_id = 3, .vlan_id = 116, .vl_id_start = 4379, .vl_id_count = 8, .rate_mbps = 240}, \
}

// Port 5: VLAN 117-120, VL-ID 4387-4418 → Port 12
#define DPDK_EXT_TX_PORT_5_TARGETS {                                                          \
    {.queue_id = 0, .vlan_id = 117, .vl_id_start = 4387, .vl_id_count = 8, .rate_mbps = 240}, \
    {.queue_id = 1, .vlan_id = 118, .vl_id_start = 4395, .vl_id_count = 8, .rate_mbps = 240}, \
    {.queue_id = 2, .vlan_id = 119, .vl_id_start = 4403, .vl_id_count = 8, .rate_mbps = 240}, \
    {.queue_id = 3, .vlan_id = 120, .vl_id_start = 4411, .vl_id_count = 8, .rate_mbps = 240}, \
}

// ==========================================
// PORT 0 ve PORT 6 → PORT 13 (100M bakır)
// ==========================================
// Port 0: 45 Mbps, Port 6: 45 Mbps = Toplam 90 Mbps

// Port 0: VLAN 105-108, VL-ID 4099-4114 → Port 13 (toplam 45 Mbps)
#define DPDK_EXT_TX_PORT_0_TARGETS {                                                         \
    {.queue_id = 0, .vlan_id = 105, .vl_id_start = 4099, .vl_id_count = 4, .rate_mbps = 45}, \
    {.queue_id = 1, .vlan_id = 106, .vl_id_start = 4103, .vl_id_count = 4, .rate_mbps = 45}, \
    {.queue_id = 2, .vlan_id = 107, .vl_id_start = 4107, .vl_id_count = 4, .rate_mbps = 45}, \
    {.queue_id = 3, .vlan_id = 108, .vl_id_start = 4111, .vl_id_count = 4, .rate_mbps = 45}, \
}

// Port 6: VLAN 121-124, VL-ID 4115-4130 → Port 13 (toplam 45 Mbps)
#define DPDK_EXT_TX_PORT_6_TARGETS {                                                         \
    {.queue_id = 0, .vlan_id = 121, .vl_id_start = 4115, .vl_id_count = 4, .rate_mbps = 45}, \
    {.queue_id = 1, .vlan_id = 122, .vl_id_start = 4119, .vl_id_count = 4, .rate_mbps = 45}, \
    {.queue_id = 2, .vlan_id = 123, .vl_id_start = 4123, .vl_id_count = 4, .rate_mbps = 45}, \
    {.queue_id = 3, .vlan_id = 124, .vl_id_start = 4127, .vl_id_count = 4, .rate_mbps = 45}, \
}

// All external TX port configurations
// Port 2,3,4,5 → Port 12 (1G) | Port 0,6 → Port 13 (100M)
#define DPDK_EXT_TX_PORTS_CONFIG_INIT {                                                        \
    {.port_id = 2, .dest_port = 12, .target_count = 4, .targets = DPDK_EXT_TX_PORT_2_TARGETS}, \
    {.port_id = 3, .dest_port = 12, .target_count = 4, .targets = DPDK_EXT_TX_PORT_3_TARGETS}, \
    {.port_id = 4, .dest_port = 12, .target_count = 4, .targets = DPDK_EXT_TX_PORT_4_TARGETS}, \
    {.port_id = 5, .dest_port = 12, .target_count = 4, .targets = DPDK_EXT_TX_PORT_5_TARGETS}, \
    {.port_id = 0, .dest_port = 13, .target_count = 4, .targets = DPDK_EXT_TX_PORT_0_TARGETS}, \
    {.port_id = 6, .dest_port = 13, .target_count = 4, .targets = DPDK_EXT_TX_PORT_6_TARGETS}, \
}

// Port 12 RX sources for DPDK external packets (from Port 2,3,4,5)
// Bu VL-ID aralıklarından gelen paketleri doğrula
#define PORT_12_DPDK_EXT_RX_SOURCE_COUNT 4
#define PORT_12_DPDK_EXT_RX_SOURCES_INIT {                      \
    {.source_port = 2, .vl_id_start = 4259, .vl_id_count = 32}, \
    {.source_port = 3, .vl_id_start = 4227, .vl_id_count = 32}, \
    {.source_port = 4, .vl_id_start = 4195, .vl_id_count = 32}, \
    {.source_port = 5, .vl_id_start = 4163, .vl_id_count = 32}, \
}

// Port 13 RX sources for DPDK external packets (from Port 0,6)
// VL-ID 4099-4130 aralığı (Port 0: 4099-4114, Port 6: 4115-4130)
#define PORT_13_DPDK_EXT_RX_SOURCE_COUNT 2
#define PORT_13_DPDK_EXT_RX_SOURCES_INIT {                      \
    {.source_port = 0, .vl_id_start = 4099, .vl_id_count = 16}, \
    {.source_port = 6, .vl_id_start = 4115, .vl_id_count = 16}, \
}

// ==========================================
// PTP (IEEE 1588v2) CONFIGURATION
// ==========================================
// PTP Slave implementation for synchronizing with DTN switch (master)
//
// Topology: PC → Server (DPDK/Slave) → Mellanox Switch → DTN Switch (Master)
//
// Each server port connects to 4 DTN ports via VLANs:
//   - 8 ports × 4 VLANs = 32 PTP sessions total
//
// Mode: One-step (no Follow_Up messages)
// Transport: Layer 2 (EtherType 0x88F7)
// Timestamps: Software (rte_rdtsc) for t2 and t3
//             Hardware timestamps from DTN for t1 and t4

#ifndef PTP_ENABLED
#define PTP_ENABLED 1
#endif

// PTP Queue configuration
// Using Queue 5 for both TX and RX (Queue 4 is used by External TX)
#define PTP_TX_QUEUE 5
#define PTP_RX_QUEUE 5

// PTP core configuration
// 1 PTP core per port (8 total) for accurate software timestamps
#ifndef NUM_PTP_CORES_PER_PORT
#define NUM_PTP_CORES_PER_PORT 1
#endif

// PTP VL-ID base (must not overlap with existing VL-IDs)
// Existing VL-IDs go up to ~4418, PTP starts at 4500
#define PTP_VL_ID_START 4500

// PTP timeouts (in seconds)
#define PTP_SYNC_TIMEOUT_SEC 3       // Max time to wait for Sync
#define PTP_DELAY_RESP_TIMEOUT_SEC 2 // Max time to wait for Delay_Resp

// PTP Delay_Req interval (in ms)
// After receiving Sync, wait this long before sending Delay_Req
#define PTP_DELAY_REQ_INTERVAL_MS 100

// PTP mbuf pool configuration
#define PTP_MBUF_POOL_SIZE 1024
#define PTP_MBUF_CACHE_SIZE 32

// PTP packet size (Layer 2: Ethernet + VLAN + PTP)
// Sync: 14 (ETH) + 4 (VLAN) + 44 (PTP) = 62 bytes
// Delay_Req: 14 (ETH) + 4 (VLAN) + 44 (PTP) = 62 bytes
// Delay_Resp: 14 (ETH) + 4 (VLAN) + 54 (PTP) = 72 bytes
#define PTP_MAX_PACKET_SIZE 128

// PTP statistics update interval (in seconds)
#define PTP_STATS_INTERVAL_SEC 1

// PTP raw packet debug printing (0=disabled, 1=enabled)
// Note: PTP Calc results are ALWAYS printed regardless of this setting
#ifndef PTP_RAW_DEBUG_PRINT
#define PTP_RAW_DEBUG_PRINT 0
#endif

// Number of PTP ports (DPDK ports 0-7)
#define PTP_PORT_COUNT 8

// Number of PTP sessions per port (one per VLAN)
#define PTP_SESSIONS_PER_PORT_COUNT 4

// ==========================================
// PTP SESSION CONFIGURATION (Static Table)
// ==========================================
// Split TX/RX Port Architecture:
//   - RX port: Sync ve Delay_Resp paketlerini alır (session bu port'ta yaşar)
//   - TX port: Delay_Req paketini gönderir (farklı port olabilir)
//
// Örnek (DTN Port 0):
//   - TX: Server Port 2, VLAN 97 → Mellanox → DTN Port 0
//   - RX: DTN Port 0 → Mellanox → Server Port 5, VLAN 225
//
// Her session için:
//   - rx_port_id: Sync/Delay_Resp alan port (session owner)
//   - rx_vlan: RX VLAN ID
//   - tx_port_id: Delay_Req gönderen port
//   - tx_vlan: TX VLAN ID
//   - tx_vl_idx: Delay_Req paketine yazılacak VL-IDX
// NOT: rx_vl_idx konfigüre edilmez, Sync paketinden okunur!

struct ptp_session_config
{
  uint16_t rx_port_id; // RX port ID (session lives here)
  uint16_t rx_vlan;    // RX VLAN ID (Sync/Delay_Resp)
  uint16_t tx_port_id; // TX port ID (for Delay_Req)
  uint16_t tx_vlan;    // TX VLAN ID (Delay_Req)
  uint16_t tx_vl_idx;  // TX VL-IDX (for Delay_Req)
};

// PTP Port Configuration Table
// Her entry bir PTP session tanımlar
// Session, rx_port_id üzerinde yaşar ve tx_port_id üzerinden gönderir
#define PTP_SESSION_COUNT 32 // DTN Port 0 ve DTN Port 1 için 2 session

#define PTP_SESSIONS_CONFIG_INIT {                                                                                                                        \
    /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */                                                                                        \
    {.rx_port_id = 5, .rx_vlan = 225, .tx_port_id = 2, .tx_vlan = 97, .tx_vl_idx = 4420},  /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 5, .rx_vlan = 226, .tx_port_id = 2, .tx_vlan = 98, .tx_vl_idx = 4422},  /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 5, .rx_vlan = 227, .tx_port_id = 2, .tx_vlan = 99, .tx_vl_idx = 4424},  /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 5, .rx_vlan = 228, .tx_port_id = 2, .tx_vlan = 100, .tx_vl_idx = 4426}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 4, .rx_vlan = 229, .tx_port_id = 3, .tx_vlan = 101, .tx_vl_idx = 4428}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 4, .rx_vlan = 230, .tx_port_id = 3, .tx_vlan = 102, .tx_vl_idx = 4430}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 4, .rx_vlan = 231, .tx_port_id = 3, .tx_vlan = 103, .tx_vl_idx = 4432}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 4, .rx_vlan = 232, .tx_port_id = 3, .tx_vlan = 104, .tx_vl_idx = 4434}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 7, .rx_vlan = 233, .tx_port_id = 0, .tx_vlan = 105, .tx_vl_idx = 4436}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 7, .rx_vlan = 234, .tx_port_id = 0, .tx_vlan = 106, .tx_vl_idx = 4438}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 7, .rx_vlan = 235, .tx_port_id = 0, .tx_vlan = 107, .tx_vl_idx = 4440}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 7, .rx_vlan = 236, .tx_port_id = 0, .tx_vlan = 108, .tx_vl_idx = 4442}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 6, .rx_vlan = 237, .tx_port_id = 1, .tx_vlan = 109, .tx_vl_idx = 4444}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 6, .rx_vlan = 238, .tx_port_id = 1, .tx_vlan = 110, .tx_vl_idx = 4446}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 6, .rx_vlan = 239, .tx_port_id = 1, .tx_vlan = 111, .tx_vl_idx = 4448}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 6, .rx_vlan = 240, .tx_port_id = 1, .tx_vlan = 112, .tx_vl_idx = 4450}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 3, .rx_vlan = 241, .tx_port_id = 4, .tx_vlan = 113, .tx_vl_idx = 4452}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 3, .rx_vlan = 242, .tx_port_id = 4, .tx_vlan = 114, .tx_vl_idx = 4454}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 3, .rx_vlan = 243, .tx_port_id = 4, .tx_vlan = 115, .tx_vl_idx = 4456}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 3, .rx_vlan = 244, .tx_port_id = 4, .tx_vlan = 116, .tx_vl_idx = 4458}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 2, .rx_vlan = 245, .tx_port_id = 5, .tx_vlan = 117, .tx_vl_idx = 4460}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 2, .rx_vlan = 246, .tx_port_id = 5, .tx_vlan = 118, .tx_vl_idx = 4462}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 2, .rx_vlan = 247, .tx_port_id = 5, .tx_vlan = 119, .tx_vl_idx = 4464}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 2, .rx_vlan = 248, .tx_port_id = 5, .tx_vlan = 120, .tx_vl_idx = 4466}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 1, .rx_vlan = 249, .tx_port_id = 6, .tx_vlan = 121, .tx_vl_idx = 4468}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 1, .rx_vlan = 250, .tx_port_id = 6, .tx_vlan = 122, .tx_vl_idx = 4470}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 1, .rx_vlan = 251, .tx_port_id = 6, .tx_vlan = 123, .tx_vl_idx = 4472}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 1, .rx_vlan = 252, .tx_port_id = 6, .tx_vlan = 124, .tx_vl_idx = 4474}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 0, .rx_vlan = 253, .tx_port_id = 7, .tx_vlan = 125, .tx_vl_idx = 4476}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 0, .rx_vlan = 254, .tx_port_id = 7, .tx_vlan = 126, .tx_vl_idx = 4478}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 0, .rx_vlan = 255, .tx_port_id = 7, .tx_vlan = 127, .tx_vl_idx = 4480}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
    {.rx_port_id = 0, .rx_vlan = 256, .tx_port_id = 7, .tx_vlan = 128, .tx_vl_idx = 4482}, /* DTN Port 0: RX=Port5/VLAN225, TX=Port2/VLAN97/VL-IDX4420 */ \
}

// ==========================================
// HEALTH MONITOR CONFIGURATION
// ==========================================
// Health Monitor sends periodic queries to DTN and receives status responses.
// Runs on Port 13 (eno12409) independently from PRBS traffic.
//
// Query: 64 byte packet sent every 1 second
// Response: 6 packets with VL_IDX=4484 (0x1184) in DST MAC[4:5]
// Timeout: 500ms per cycle

#ifndef HEALTH_MONITOR_ENABLED
#define HEALTH_MONITOR_ENABLED 1
#endif

#endif /* CONFIG_H */

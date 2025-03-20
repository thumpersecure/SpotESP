// Spot ESP - Defensive Firmware for ESP32-2432S028 (Cheap Yellow Display)
// Detects Wi-Fi attacks, BLE threats, LAN anomalies with a touchscreen UI
// Written for ESP-IDF in C++

#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/inet.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_timer.h"

// Touchscreen + Display
#include "tftspi.h"
#include "tft.h"
#include "xpt2046.h"

// Bluetooth (NimBLE)
#include "NimBLEDevice.h"

#define TAG "SPOT_ESP"
#define TFT_TOUCH_IRQ 36 // Example GPIO
#define WIFI_SCAN_INTERVAL_MS 500
#define BLE_SCAN_DURATION 5
#define WIFI_CONNECT_TIMEOUT_MS 10000

// Globals
static uint32_t deauth_count = 0;
static bool wifi_connected = false;
static std::string current_ssid = "";
static std::string gateway_ip = "";
std::vector<std::string> alerts;

// === Utility Functions ===
void log_alert(const char* message) {
    ESP_LOGW(TAG, "ALERT: %s", message);
    alerts.push_back(std::string(message));
    if (alerts.size() > 10) alerts.erase(alerts.begin()); // Limit to last 10 alerts
    TFT_fillRect(0, 220, 320, 20, TFT_RED);
    TFT_print((char*)message, CENTER, 220);
}

std::string get_ip_str(ip4_addr_t ip) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));
    return std::string(buf);
}

// === UI Setup ===
void ui_init() {
    tft_disp_type = TFT_TYPE_ILI9341;
    TFT_PinsInit();
    TFT_SPIInit();
    TFT_setRotation(PORTRAIT);
    TFT_fillScreen(TFT_BLACK);
    TFT_setFont(DEFAULT_FONT, NULL);
    TFT_print("Spot ESP - Defense Mode", CENTER, 10);
    TFT_drawRect(0, 220, 320, 20, TFT_WHITE); // Alert area
}

// === Wi-Fi Sniffer Callback ===
void wifi_sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t fc = (payload[0] << 8) | payload[1];
    uint8_t subtype = (fc & 0xF0) >> 4;

    if (subtype == 12) { // Deauth
        deauth_count++;
        if (deauth_count % 10 == 0) {
            log_alert("Deauth Attack Detected");
        }
    }

    if (subtype == 4) { // Probe Request
        // TODO: Add detection for probe flood
    }
}

// === Wi-Fi Detection Task ===
void wifi_sniff_task(void* pvParameters) {
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_callback);

    uint8_t channel = 1;
    while (1) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        channel = (channel % 11) + 1;
        vTaskDelay(pdMS_TO_TICKS(WIFI_SCAN_INTERVAL_MS));
    }
}

// === BLE Scan Callback ===
class BLECallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* device) {
        std::string name = device->getName();
        if (name.find("Flipper") != std::string::npos || name.find("HC-") != std::string::npos) {
            log_alert(("BLE Threat: " + name).c_str());
        }
    }
};

// === BLE Detection Task ===
void ble_scan_task(void* pvParameters) {
    NimBLEDevice::init("");
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setAdvertisedDeviceCallbacks(new BLECallbacks());
    scan->setActiveScan(true);

    while (1) {
        scan->start(BLE_SCAN_DURATION, false);
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

// === LAN Anomaly Detection Task ===
void lan_monitor_task(void* pvParameters) {
    while (!wifi_connected) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    while (1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(80);
            inet_pton(AF_INET, gateway_ip.c_str(), &addr.sin_addr);

            int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
            if (res < 0) {
                log_alert("LAN anomaly: Gateway unreachable");
            }
            close(sock);
        }
        vTaskDelay(pdMS_TO_TICKS(15000));
    }
}

// === Wi-Fi Connection (for LAN Monitoring) ===
void connect_to_wifi() {
    wifi_config_t sta_config = {};
    strcpy((char*)sta_config.sta.ssid, "YOUR_WIFI_SSID");
    strcpy((char*)sta_config.sta.password, "YOUR_WIFI_PASS");

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_connect());

    uint64_t start = esp_timer_get_time();
    while ((esp_timer_get_time() - start) < WIFI_CONNECT_TIMEOUT_MS * 1000) {
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            current_ssid = std::string((char*)ap_info.ssid);
            wifi_connected = true;
            esp_netif_ip_info_t ip_info;
            esp_netif_t* netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
            esp_netif_get_ip_info(netif, &ip_info);
            gateway_ip = get_ip_str(ip_info.gw);
            log_alert("Connected to Wi-Fi");
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    if (!wifi_connected) {
        log_alert("Wi-Fi connection failed");
    }
}

// === Main App Entry Point ===
extern "C" void app_main() {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ui_init();
    log_alert("Spot ESP Initialized");

    ESP_ERROR_CHECK(esp_wifi_init(&WIFI_INIT_CONFIG_DEFAULT()));
    connect_to_wifi();

    xTaskCreate(&wifi_sniff_task, "wifi_sniff", 4096, NULL, 5, NULL);
    xTaskCreate(&ble_scan_task, "ble_scan", 4096, NULL, 5, NULL);
    xTaskCreate(&lan_monitor_task, "lan_monitor", 4096, NULL, 5, NULL);
}
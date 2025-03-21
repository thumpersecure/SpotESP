#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_bt.h>
#include <esp_bt_main.h>
#include <esp_bt_device.h>
#include <esp_bt_gap.h>
#include <esp_gap_ble_api.h>
#include <SD.h>
#include <SPI.h>
#include <TFT_eSPI.h>
#include <XPT2046_Touchscreen.h>
#include <ArduinoOTA.h>

// ********** Configuration & Pin Definitions **********
// Display pins (configured in TFT_eSPI library's User_Setup.h as well)
#define TFT_BACKLIGHT_PIN 21       // Backlight control (CYD v1 uses 21, v2 uses 27)
#define TFT_BACKLIGHT_ON HIGH
// Touchscreen pins (already defined in code for XPT2046_Touchscreen usage)
#define XPT2046_CS   33  // Touch chip select
#define XPT2046_IRQ  36  // Touch IRQ (T_IRQ pin)

// SD card SPI CS pin (adjust based on board wiring)
#define SD_CS  4

// Wi-Fi scanning parameters
static const int WIFI_CHANNEL_HOP_INTERVAL_MS = 500;  // channel dwell time
static const uint8_t WIFI_CHANNEL_MIN = 1;
static const uint8_t WIFI_CHANNEL_MAX = 11;  // (use 13 if in EU etc.)

// Thresholds for detection
static const int PROBE_REQ_THRESHOLD = 50;    // e.g. >50 probe req per interval => attack
static const int DEAUTH_THRESHOLD = 5;        // >5 deauth/disassoc frames in short time
// (Threshold can be tuned or even count every occurrence as an alert for simplicity)

// ********** Global Variables & Structures **********
TFT_eSPI tft = TFT_eSPI();                 // TFT display object
SPIClass touchscreenSPI(VSPI);             // SPI bus for touchscreen (using VSPI)
XPT2046_Touchscreen touch(XPT2046_CS, XPT2046_IRQ);  // Touchscreen controller

// Logging
File logFile;
String logFileName;
struct LogEvent {                           // structure for an event log entry
  String timestamp;
  String type;
  String description;
};
QueueHandle_t logQueue;                    // queue to offload log writing to SD

// Wi-Fi attack detection counters/state
volatile unsigned long probeCount = 0;
volatile unsigned long deauthCount = 0;
volatile unsigned long disassocCount = 0;

// Known network info for rogue AP detection and ARP monitoring
String protectedSSID = "";                 // SSID of the network to protect (if any)
uint8_t gatewayMAC[6];                     // Gateway router’s MAC (learned after connect)
bool haveGatewayMAC = false;

// Menu/UI state
enum Screen { SCREEN_MAIN, SCREEN_LOGS, SCREEN_SETTINGS, SCREEN_MONITOR } currentScreen;
bool redraw = true;                        // flag to redraw screen
unsigned long lastTouchTime = 0;           // last touch timestamp (for debouncing)

// ********** Utility Functions (Time, Logging, etc.) **********
String getTimestamp() {
  // Returns current timestamp as string "[HH:MM:SS]" (or uptime if RTC not set)
  char buffer[12];
  // Use RTC time if set, otherwise use millis()/uptime
  if(time(nullptr) > 100000) {
    // RTC time available (epoch non-zero)
    struct tm timeinfo;
    getLocalTime(&timeinfo);
    strftime(buffer, sizeof(buffer), "[%H:%M:%S]", &timeinfo);
  } else {
    // Fallback to uptime in seconds
    unsigned long sec = millis() / 1000;
    unsigned int hr = sec / 3600;
    unsigned int min = (sec % 3600) / 60;
    unsigned int s = sec % 60;
    snprintf(buffer, sizeof(buffer), "[%02u:%02u:%02u]", hr, min, s);
  }
  return String(buffer);
}

void logEvent(const String &type, const String &desc) {
  // Create log entry and send to queue for writing
  LogEvent ev;
  ev.timestamp = getTimestamp();
  ev.type = type;
  ev.description = desc;
  if(logQueue != NULL) {
    xQueueSend(logQueue, &ev, 0);  // send to queue (non-blocking)
  }
  Serial.println(ev.timestamp + " " + type + ": " + desc);  // debug output
}

// ********** Wi-Fi Promiscuous Packet Sniffer Callback **********
// Called by ESP32 Wi-Fi driver for each packet captured in promiscuous mode.
void IRAM_ATTR wifiSnifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if(type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) {
    return; // we care only about management and data frames for this application
  }
  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*) buf;
  const uint8_t *payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;  // length of packet
  // Management frame header structure (IEEE 802.11)
  struct WifiMgmtHdr {
    uint16_t frameCtrl;
    uint16_t duration;
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint16_t seqCtrl;
    // followed by frame body
  } __attribute__((packed));
  if(type == WIFI_PKT_MGMT) {
    const WifiMgmtHdr *mh = (const WifiMgmtHdr*) payload;
    uint16_t fctl = mh->frameCtrl;
    // Check management subtype bits (frame control bits 4-7) [oai_citation_attribution:12‡gist.github.com](https://gist.github.com/tobozo/681d79c937ca3b5fac711bec9438918e#:~:text=if%28buf%5B12%5D%20%3D%3D%200xA0%20,count%2B%2B%3B%20%7D%20else)
    if((fctl & 0x0F00) == 0x0C00) {  // 0x0C00 -> deauthentication frame [oai_citation_attribution:13‡gist.github.com](https://gist.github.com/tobozo/681d79c937ca3b5fac711bec9438918e#:~:text=if%20,)
      deauthCount++;
    } else if((fctl & 0x0F00) == 0x0A00) {  // 0x0A00 -> disassociation frame [oai_citation_attribution:14‡gist.github.com](https://gist.github.com/tobozo/681d79c937ca3b5fac711bec9438918e#:~:text=if%28buf%5B12%5D%20%3D%3D%200xA0%20,count%2B%2B%3B%20%7D%20else)
      disassocCount++;
    } else if((fctl & 0x0F00) == 0x0400) {  // 0x0400 -> probe request frame
      probeCount++;
    } else if((fctl & 0x0F00) == 0x0800) {
      // Beacon frame (subtype 0x08). Could collect SSID here for rogue AP detection.
      // For simplicity, we rely on active scanning instead of parsing beacons in this code.
    }
    // Note: We can also detect Probe Responses (0x0500), Authentication (0x0B00), etc., if needed.
  } else if(type == WIFI_PKT_DATA) {
    // Data frame – check if it contains an ARP packet.
    // We look for ARP EtherType (0x0806) in the LLC header if present.
    // Simplified approach: scan payload for the ARP EtherType pattern.
    // Caution: This will only work for unencrypted frames (e.g., on open networks or our own network).
    for(int i = 0; i < len - 2; ++i) {
      if(payload[i] == 0x08 && payload[i+1] == 0x06) {  // found 0x0806
        // This looks like an ARP packet in the payload
        // Parse basic ARP fields: sender IP/MAC and target IP.
        if(len >= i+28) { // ARP packet minimum length from EtherType to target IP
          // ARP packet structure:
          // offset i: 0x08 0x06 (EtherType)
          // offset i+2..3: Hardware type, i+4..5: Protocol type, i+6: HW addr len, i+7: Proto addr len
          // offset i+8..9: Opcode (0x0002 = reply, 0x0001 = request)
          uint16_t opcode = (payload[i+8] << 8) | payload[i+9];
          // Sender MAC: i+10 .. i+15, Sender IP: i+16 .. i+19
          // Target MAC: i+20 .. i+25, Target IP: i+26 .. i+29
          uint8_t senderMac[6];
          uint8_t targetMac[6];
          uint32_t senderIP, targetIP;
          memcpy(senderMac, payload + i + 10, 6);
          memcpy(&senderIP, payload + i + 16, 4);
          memcpy(targetMac, payload + i + 20, 6);
          memcpy(&targetIP, payload + i + 26, 4);
          IPAddress sIP(senderIP);
          IPAddress tIP(targetIP);
          // Check for anomalies:
          if(haveGatewayMAC && gatewayMAC[0] != 0) {
            // If the ARP is a reply and target IP is our IP, but MAC doesn't match our ESP32, that's a duplicate IP situation.
            if(opcode == 0x0002 && tIP == WiFi.localIP() && memcmp(senderMac, WiFi.macAddress().c_str(), 6) != 0) {
              logEvent("LAN", "Duplicate IP detected: " + sIP.toString() + " is also using our IP!");
            }
            // If the ARP sender IP matches the gateway and MAC is different from known gateway MAC -> ARP spoofing
            if(sIP == WiFi.gatewayIP() && memcmp(senderMac, gatewayMAC, 6) != 0) {
              logEvent("LAN", "Possible ARP spoof: Gateway " + String(sIP.toString()) + " MAC changed!");
            }
          }
        }
        break; // stop scanning this payload after handling ARP
      }
    }
  }
}

// ********** Bluetooth Callbacks (Classic GAP & BLE) **********
static void btGapCallback(esp_bt_gap_cb_event_t event, esp_bt_gap_cb_param_t *param) {
  if(event == ESP_BT_GAP_DISC_RES_EVT) {
    // Classic BT device found
    char bda_str[18];
    esp_bt_gap_resolve_eir_data(param->disc_res.prop, ESP_BT_GAP_EIR_TYPE_CMPL_LOCAL_NAME); // ensure EIR parsed to get name in properties
    // Iterate through properties to find name
    char deviceName[248] = {0};
    for(int i = 0; i < param->disc_res.num_prop; ++i) {
      if(param->disc_res.prop[i].type == ESP_BT_GAP_DEV_PROP_BDNAME) {
        // Device name in property
        int len = param->disc_res.prop[i].len;
        if(len > 0) {
          memcpy(deviceName, param->disc_res.prop[i].val, len);
          deviceName[len] = 0;
        }
      }
      else if(param->disc_res.prop[i].type == ESP_BT_GAP_DEV_PROP_EIR) {
        // Extract name from EIR if available
        uint8_t peer_bdname_len = 0;
        esp_bt_gap_resolve_eir_data((uint8_t*)param->disc_res.prop[i].val, ESP_BT_EIR_TYPE_CMPL_LOCAL_NAME, &peer_bdname_len);
        // This API isn't straightforward in Arduino, using an alternative approach above.
      }
    }
    String nameStr = String(deviceName);
    String addrStr;
    if(esp_bt_gap_get_cod(param->disc_res.bda) != 0) {
      // Format address
      sprintf(bda_str, "%02X:%02X:%02X:%02X:%02X:%02X",
              param->disc_res.bda[0], param->disc_res.bda[1], param->disc_res.bda[2],
              param->disc_res.bda[3], param->disc_res.bda[4], param->disc_res.bda[5]);
      addrStr = String(bda_str);
    }
    // Check for known malicious device names
    if(nameStr.indexOf("Flipper") != -1 || nameStr.indexOf("FLIPPER") != -1) {
      logEvent("Bluetooth", "Flipper Zero device detected (" + nameStr + " @ " + addrStr + ")");
    }
    if(nameStr.indexOf("HC-05") != -1 || nameStr.indexOf("HC-06") != -1) {
      logEvent("Bluetooth", "Possible BT skimmer module found (" + nameStr + ")");
    }
    // We could also log any device discovery for user reference
    // e.g., logEvent("BT", "Discovered BT device: " + nameStr + " [" + addrStr + "]");
  }
  else if(event == ESP_BT_GAP_DISC_STATE_CHANGED_EVT) {
    if(param->disc_st_chg.state == ESP_BT_GAP_DISCOVERY_COMPLETE) {
      // Discovery finished, restart scanning for classic BT
      esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_GENERAL_INQUIRY, 10, 0);
    }
  }
}

static void bleScanCallback(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  if(event == ESP_GAP_BLE_SCAN_RESULT_EVT) {
    esp_ble_gap_cb_param_t *sr = param;
    if(sr->scan_rst.search_evt == ESP_BT_GAP_DISC_RES_EVT || sr->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
      // BLE device found (advertisement)
      // Parse advertisement data for name or flags
      uint8_t advNameLen = 0;
      const uint8_t *advName = esp_ble_resolve_adv_data(sr->scan_rst.ble_adv, ESP_BLE_AD_TYPE_NAME_CMPL, &advNameLen);
      String name = "";
      if(advName != NULL && advNameLen > 0) {
        name = String((const char*)advName).substring(0, advNameLen);
      }
      // Check for BLE spam characteristics (e.g., specific manufacturer data patterns could be checked here)
      // For demonstration, if many adverts from same device in short time or specific name, flag it.
      static uint8_t flipperAdvPrefix[] = {0x42, 0x4C, 0x45, 0x5F}; // "BLE_" maybe as an example prefix
      // (In reality, Flipper BLE name might contain "Flipper", which we already check via name.)
      if(name.indexOf("Flipper") != -1) {
        logEvent("Bluetooth", "Flipper Zero BLE Advertiser detected (\"" + name + "\")");
      }
      // BLE spam detection: if a single device sends a large volume of advertising packets.
      // We could count RSSI hits for same address.
      // (For simplicity, not fully implemented here due to complexity of maintaining state across events.)
    } else if(sr->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_CMPL_EVT) {
      // BLE scan complete, restart scanning (continuous scanning)
      esp_ble_gap_start_scanning(5); // scan in 5-second bursts
    }
  }
}

// ********** FreeRTOS Task: Wi-Fi Channel Hopper & Detector **********
void wifiScanTask(void *param) {
  uint8_t currentChannel = WIFI_CHANNEL_MIN;
  while(true) {
    // Rotate Wi-Fi channel to capture packets on all channels
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    currentChannel++;
    if(currentChannel > WIFI_CHANNEL_MAX) currentChannel = WIFI_CHANNEL_MIN;
    // Periodically evaluate counts to detect attacks
    static unsigned long lastCheck = 0;
    unsigned long now = millis();
    if(now - lastCheck >= 1000) {  // every 1 second
      // Check and log Wi-Fi attacks based on thresholds
      if(deauthCount > DEAUTH_THRESHOLD || disassocCount > DEAUTH_THRESHOLD) {
        logEvent("Wi-Fi", "Possible Deauth attack! (" + String(deauthCount) + " deauth/disassoc frames)");
      }
      if(probeCount > PROBE_REQ_THRESHOLD) {
        logEvent("Wi-Fi", "Probe request flood detected (" + String(probeCount) + " probes)");
      }
      // Reset counters for next interval
      deauthCount = disassocCount = 0;
      probeCount = 0;
      lastCheck = now;
    }
    vTaskDelay(WIFI_CHANNEL_HOP_INTERVAL_MS / portTICK_PERIOD_MS);
  }
}

// ********** FreeRTOS Task: SD Log Writer **********
void sdLogTask(void *param) {
  LogEvent ev;
  for(;;) {
    if(xQueueReceive(logQueue, &ev, portMAX_DELAY) == pdTRUE) {
      // Write the log event to SD file
      if(logFile) {
        logFile.print(ev.timestamp + " [" + ev.type + "] " + ev.description + "\n");
        logFile.flush();
      }
      // If on live monitor screen, we could also update a live log view (optional)
      // (For simplicity, live updates are handled by reading log file when viewing)
    }
  }
}

// ********** User Interface Rendering Functions **********
void drawMainMenu() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  tft.setCursor(40, 40);
  tft.println("Spot ESP - Main Menu");
  tft.drawRect(20, 80, 200, 40, TFT_WHITE);
  tft.setCursor(30, 90);
  tft.print("Live Threat Monitor");
  tft.drawRect(20, 130, 200, 40, TFT_WHITE);
  tft.setCursor(30, 140);
  tft.print("View Logs");
  tft.drawRect(20, 180, 200, 40, TFT_WHITE);
  tft.setCursor(30, 190);
  tft.print("Settings");
}

void drawMonitorScreen() {
  tft.fillScreen(TFT_DARKGREY);
  tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.println("Live Threats:");
  tft.drawLine(0, 30, 240, 30, TFT_WHITE);
  // In a real implementation, we might keep a list of recent active threats to display.
  tft.setTextSize(1);
  tft.setCursor(10, 40);
  tft.println("Monitoring Wi-Fi & BT...");
  tft.setCursor(10, 60);
  tft.println("Tap to refresh / Back");
}

void drawLogsScreen() {
  tft.fillScreen(TFT_NAVY);
  tft.setTextColor(TFT_YELLOW, TFT_NAVY);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.println("Logs - " + logFileName);
  tft.drawLine(0, 30, 240, 30, TFT_WHITE);
  tft.setTextSize(1);
  // Read the last N lines from the log file to display (simple approach)
  if(logFile) {
    logFile.seek(0);
    // Display up to, say, 10 lines
    int lines = 0;
    String line;
    while(logFile.available() && lines < 10) {
      line = logFile.readStringUntil('\n');
      if(line.length() > 0) {
        tft.println(line);
        lines++;
      }
    }
    // If log is longer, indicate "..." or allow scrolling in a more advanced implementation
    if(logFile.available()) {
      tft.setTextColor(TFT_LIGHTGREY, TFT_NAVY);
      tft.println("... (see SD for full log)");
    }
    // Reset file pointer for continuous logging
    logFile.seek(logFile.size());
  } else {
    tft.setTextColor(TFT_RED, TFT_NAVY);
    tft.println("No log file open.");
  }
  tft.setTextColor(TFT_CYAN, TFT_NAVY);
  tft.println("\nTap to go back");
}

void drawSettingsScreen() {
  tft.fillScreen(TFT_GREEN);
  tft.setTextColor(TFT_BLACK, TFT_GREEN);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.println("Settings");
  tft.drawLine(0, 30, 240, 30, TFT_BLACK);
  tft.setTextSize(1);
  tft.setCursor(10, 50);
  tft.println("- Wi-Fi OTA: " + String(WiFi.isConnected() ? "Ready" : "Not connected"));
  tft.setCursor(10, 70);
  tft.println("- Protected SSID: " + (protectedSSID.length() ? protectedSSID : String("None")));
  tft.setCursor(10, 90);
  tft.println("- SD Logging: " + String(SD.begin(SD_CS) ? "Enabled" : "Error"));
  tft.setCursor(10, 120);
  tft.setTextColor(TFT_BLUE, TFT_GREEN);
  tft.println("Tap to return");
}

// ********** Setup Function **********
void setup() {
  Serial.begin(115200);
  // Initialize display and touch
  tft.init();
  tft.setRotation(1);  // 1 or 3 for landscape mode
  pinMode(TFT_BACKLIGHT_PIN, OUTPUT);
  digitalWrite(TFT_BACKLIGHT_PIN, TFT_BACKLIGHT_ON);
  touchscreenSPI.begin(25, 39, 32, XPT2046_CS);  // SCK=25, MISO=39, MOSI=32 for touch [oai_citation_attribution:15‡randomnerdtutorials.com](https://randomnerdtutorials.com/cheap-yellow-display-esp32-2432s028r/#:~:text=,25%20%20%20%2F%2F%20T_CLK)
  touch.begin(touchscreenSPI);
  touch.setRotation(1);  // align touch coordinates with display rotation

  // Initialize Wi-Fi in promiscuous (sniffer) mode
  WiFi.mode(WIFI_MODE_NULL);  // not connected initially (null mode) to allow sniffing
  // Configure Wi-Fi sniffer
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_promiscuous(true);
  wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(wifiSnifferCallback);
  esp_wifi_set_channel(WIFI_CHANNEL_MIN, WIFI_SECOND_CHAN_NONE);

  // Initialize Bluetooth (Classic + BLE dual mode)
  btStart();                // initialize BT controller
  esp_bluedroid_init();     
  esp_bluedroid_enable();
  // Register callbacks for Classic GAP and BLE
  esp_bt_gap_register_callback(btGapCallback);
  esp_ble_gap_register_callback(bleScanCallback);
  // Start scanning Classic BT and BLE
  esp_bt_gap_set_scan_mode(ESP_BT_CONNECTABLE, ESP_BT_GENERAL_DISCOVERABLE);
  esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_GENERAL_INQUIRY, 10, 0);
  esp_ble_scan_params_t bleScanParams = {
    .scan_type = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval = 0x50,
    .scan_window = 0x30,
    .scan_duplicate = BLE_SCAN_DUPLICATE_DISABLE
  };
  esp_ble_gap_set_scan_params(&bleScanParams);
  esp_ble_gap_start_scanning(5);

  // Initialize SD card and open log file
  if(SD.begin(SD_CS)) {
    // Create a new log file with date or increment if exists
    // (If no RTC, use a single file or an incrementing index)
    logFileName = "log_" + String((uint32_t)(ESP.getEfuseMac() & 0xFFFF), HEX) + ".txt";  // unique name per device (fallback)
    logFile = SD.open(logFileName.c_str(), FILE_APPEND);
    if(!logFile) {
      Serial.println("Failed to open log file on SD");
    }
  } else {
    Serial.println("SD card initialization failed!");
  }

  // Initialize OTA (if Wi-Fi credentials provided or connected)
  // (In this version, we start OTA only when WiFi is connected in settings manually)
  ArduinoOTA.setHostname("Spot-ESP32");
  ArduinoOTA.onStart([]() {
    logEvent("OTA", "Firmware update started");
  });
  ArduinoOTA.onEnd([]() {
    logEvent("OTA", "Firmware update completed");
  });
  ArduinoOTA.onError([](ota_error_t error) {
    logEvent("OTA", "OTA Error: " + String(error));
  });
  // (We will call ArduinoOTA.begin() after connecting to WiFi in settings, if implemented)

  // Create log queue and tasks
  logQueue = xQueueCreate(20, sizeof(LogEvent));
  if(logQueue == NULL) {
    Serial.println("Failed to create log queue!");
  }
  // Launch background tasks: Wi-Fi scanner and log writer
  xTaskCreatePinnedToCore(wifiScanTask, "WiFiScan", 4096, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(sdLogTask, "LogWriter", 4096, NULL, 1, NULL, 1);

  // Show main menu initially
  currentScreen = SCREEN_MAIN;
  drawMainMenu();
  Serial.println("Setup complete. Spot ESP is now monitoring...");
}

// ********** Main Loop **********
void loop() {
  // Handle UI touch input
  if(touch.touched()) {
    TS_Point p = touch.getPoint();
    // The XPT2046_Touchscreen library returns raw touch coordinates.
    // Map raw touch coordinates to screen coordinates (simple scaling based on rotation).
    // For simplicity, assume touch and display are aligned and calibrated.
    int tx = map(p.x, 0, 240, 0, 240);
    int ty = map(p.y, 0, 320, 0, 320);
    // Debounce touch
    if(millis() - lastTouchTime > 300) {
      lastTouchTime = millis();
      if(currentScreen == SCREEN_MAIN) {
        // Determine which menu item was touched
        if(tx > 20 && tx < 220) {
          if(ty > 80 && ty < 120) {
            // Live Threat Monitor
            currentScreen = SCREEN_MONITOR;
            redraw = true;
          } else if(ty > 130 && ty < 170) {
            // View Logs
            currentScreen = SCREEN_LOGS;
            redraw = true;
          } else if(ty > 180 && ty < 220) {
            // Settings
            currentScreen = SCREEN_SETTINGS;
            redraw = true;
          }
        }
      } else if(currentScreen == SCREEN_MONITOR) {
        // Any touch on monitor screen returns to main (or refreshes)
        currentScreen = SCREEN_MAIN;
        redraw = true;
      } else if(currentScreen == SCREEN_LOGS) {
        // Go back to main menu on touch
        currentScreen = SCREEN_MAIN;
        redraw = true;
      } else if(currentScreen == SCREEN_SETTINGS) {
        // In a real implementation, we might toggle settings or initiate Wi-Fi connect for OTA.
        // Here, any touch just returns to main menu.
        currentScreen = SCREEN_MAIN;
        redraw = true;
      }
    }
  }

  // If screen state changed, redraw appropriate screen
  if(redraw) {
    redraw = false;
    switch(currentScreen) {
      case SCREEN_MAIN:     drawMainMenu(); break;
      case SCREEN_MONITOR:  drawMonitorScreen(); break;
      case SCREEN_LOGS:     drawLogsScreen(); break;
      case SCREEN_SETTINGS: drawSettingsScreen(); break;
    }
  }

  // If connected to Wi-Fi, handle OTA
  if(WiFi.isConnected()) {
    ArduinoOTA.handle();
  }

  // (Optional) We could periodically update monitor screen with any active threat flags or counts.

  delay(50);  // small delay to throttle loop
}
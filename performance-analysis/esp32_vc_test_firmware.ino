
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <FS.h>
#include <SPIFFS.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

const char* apSSID = "ESP32-VC-Uploader";
const char* apPassword = "12345678";

const char* staSSID = "<<YOUR WIFI SSID>>";
const char* staPassword = "<<YOUR WIFI PASSWORD>>";

const char* verificationURL = "https://<<YOUR GATEWAY IP>>/vc/verify";

AsyncWebServer server(80);
bool onWiFi = false;

int attempt = 0;
const int totalAttempts = 100;

const char* csvPath = "/vc_results.csv";

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><title>Upload VC</title></head><body>
<h2>Upload Verifiable Credential</h2>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="vc">
  <input type="submit" value="Upload">
</form>
</body></html>
)rawliteral";

void setup() {
  Serial.begin(115200);
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed");
    return;
  }

  if (SPIFFS.exists(csvPath)) {
    SPIFFS.remove(csvPath);
  }
  File f = SPIFFS.open(csvPath, FILE_WRITE);
  f.println("Attempt,Timestamp,VCSize,HeapBefore,HeapAfterRead,HeapAfterHTTP,MaxAllocHeap,WiFiTime,VCReadTime,PostTime,TotalTime,HTTPCode,VCStatus");
  f.close();

  WiFi.softAP(apSSID, apPassword);
  Serial.println("[AP MODE] Connect to: " + String(apSSID));
  Serial.println("IP address: " + WiFi.softAPIP().toString());

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
    request->send_P(200, "text/html", index_html);
  });

  server.on("/upload", HTTP_POST, [](AsyncWebServerRequest *request){
    request->send(200, "text/plain", "File uploaded. Rebooting...");
    delay(2000);
    ESP.restart();
  }, handleUpload);

  server.on("/delete", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!onWiFi) {
      request->send(403, "text/plain", "Not allowed in AP mode");
      return;
    }
    if (SPIFFS.exists("/vc.json")) {
      SPIFFS.remove("/vc.json");
      request->send(200, "text/plain", "\xE2\x9C\x85 VC deleted. Restarting...");
      delay(2000);
      ESP.restart();
    } else {
      request->send(404, "text/plain", "\xE2\x9D\x8C No VC file found");
    }
  });

  server.on("/download_csv", HTTP_GET, [](AsyncWebServerRequest *request){
    request->send(SPIFFS, csvPath, "text/csv");
  });

  server.begin();
}

void loop() {
  if (SPIFFS.exists("/vc.json") && !onWiFi) {
    delay(5000);
    WiFi.disconnect();

    Serial.println("\n[INFO] Found /vc.json. Connecting to WiFi...");
    WiFi.mode(WIFI_STA);

    unsigned long wifiStart = millis();
    WiFi.begin(staSSID, staPassword);
    while (WiFi.status() != WL_CONNECTED) {
      delay(500);
    }
    unsigned long wifiTime = millis() - wifiStart;

    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("[CONNECTED] IP: " + WiFi.localIP().toString());
      onWiFi = true;
      for (int i = 0; i < totalAttempts; i++) {
        delay(2000);
        verifyVC(i + 1, wifiTime);
      }
    }
  }
  delay(1000);
}

void handleUpload(AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final) {
  static File file;
  if (index == 0) file = SPIFFS.open("/vc.json", FILE_WRITE);
  if (file) file.write(data, len);
  if (final) file.close();
}

void verifyVC(int attempt, unsigned long wifiTime) {
  File file = SPIFFS.open("/vc.json", FILE_READ);
  if (!file) return;
  uint32_t heapBefore = ESP.getFreeHeap();
  uint32_t maxAlloc = ESP.getMaxAllocHeap();

  unsigned long readStart = millis();
  String payload = file.readString();
  unsigned long readTime = millis() - readStart;
  file.close();
  uint32_t heapAfterRead = ESP.getFreeHeap();

  HTTPClient http;
  http.begin(verificationURL);
  http.addHeader("Content-Type", "application/json");

  unsigned long postStart = millis();
  int httpCode = http.POST(payload);
  unsigned long postTime = millis() - postStart;
  uint32_t heapAfterHTTP = ESP.getFreeHeap();
  unsigned long totalTime = readTime + postTime;

  String vcStatus = "N/A";
  if (httpCode > 0) {
    String response = http.getString();
    DynamicJsonDocument doc(512);
    DeserializationError err = deserializeJson(doc, response);
    if (!err && doc.containsKey("status")) vcStatus = doc["status"].as<String>();
  }
  http.end();

  File f = SPIFFS.open(csvPath, FILE_APPEND);
  f.printf("%d,%lu,%d,%d,%d,%d,%d,%lu,%lu,%lu,%lu,%d,\"%s\"\n",
           attempt, millis(), payload.length(), heapBefore, heapAfterRead, heapAfterHTTP,
           maxAlloc, wifiTime, readTime, postTime, totalTime, httpCode, vcStatus.c_str());
  f.close();

  Serial.println("[VC VERIFY] Attempt #" + String(attempt));
  Serial.printf("VC read: %lu ms, POST: %lu ms, Total: %lu ms, Heap: %d -> %d -> %d\n",
                readTime, postTime, totalTime, heapBefore, heapAfterRead, heapAfterHTTP);
}

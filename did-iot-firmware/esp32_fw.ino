#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <FS.h>
#include <SPIFFS.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/sha256.h"
#define VERIFY_SIGNATURE 0
#if VERIFY_SIGNATURE
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

const char* apSSID = "ESP32-VC-Uploader";
const char* apPassword = "12345678";

const char* staSSID = "?????????";
const char* staPassword = "????????";

const char* verificationURL = "http://192.168.68.61:8000/vp/verify";
const char* firmwareFile = "/firmware.bin";

AsyncWebServer server(80);
bool onWiFi = false;

bool verifyFirmwareFile(const char* path, const char* expected) {
  if (!SPIFFS.exists(path)) {
    Serial.println("[FW] File not found");
    return false;
  }
  File fw = SPIFFS.open(path, FILE_READ);
  if (!fw) {
    Serial.println("[FW] Failed to open file");
    return false;
  }
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  uint8_t buf[512];
  while (fw.available()) {
    size_t len = fw.read(buf, sizeof(buf));
    mbedtls_sha256_update(&ctx, buf, len);
  }
  uint8_t out[32];
  mbedtls_sha256_finish(&ctx, out);
  fw.close();
  char hex[65];
  for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", out[i]);
  bool ok = strcmp(hex, expected) == 0;
  Serial.println(ok ? "[FW] Hash match" : "[FW] Hash mismatch");
  return ok;
}

#if VERIFY_SIGNATURE
const char* issuerPubKeyPem = "-----BEGIN PUBLIC KEY-----\nYOUR PUBLIC KEY HERE\n-----END PUBLIC KEY-----\n";

int b64Index(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

size_t decodeBase64(const char* src, size_t len, uint8_t* out) {
  int val = 0, valb = -8;
  size_t outLen = 0;
  for (size_t i = 0; i < len; i++) {
    int d = b64Index(src[i]);
    if (d == -1) {
      if (src[i] == '=') break;
      continue;
    }
    val = (val << 6) + d;
    valb += 6;
    if (valb >= 0) {
      out[outLen++] = (val >> valb) & 0xFF;
      valb -= 8;
    }
  }
  return outLen;
}

size_t decodeBase64Url(const char* src, uint8_t* out) {
  String s = String(src);
  s.replace('-', '+');
  s.replace('_', '/');
  while (s.length() % 4 != 0) s += '=';
  return decodeBase64(s.c_str(), s.length(), out);
}

void canonicalize(JsonVariant v, String& out) {
  if (v.is<JsonObject>()) {
    JsonObject obj = v.as<JsonObject>();
    std::vector<String> keys;
    for (JsonPair kv : obj) keys.push_back(String(kv.key().c_str()));
    std::sort(keys.begin(), keys.end());
    out += '{';
    bool first = true;
    for (String& k : keys) {
      if (!first) out += ',';
      first = false;
      out += '"' + k + "":"";
      canonicalize(obj[k], out);
    }
    out += '}';
  } else if (v.is<JsonArray>()) {
    JsonArray arr = v.as<JsonArray>();
    out += '[';
    for (size_t i = 0; i < arr.size(); i++) {
      if (i) out += ',';
      canonicalize(arr[i], out);
    }
    out += ']';
  } else if (v.is<const char*>()) {
    out += '"';
    out += v.as<const char*>();
    out += '"';
  } else {
    out += v.as<String>();
  }
}

bool verifySignature(const JsonDocument& doc) {
  if (!doc.containsKey("proof")) {
    Serial.println("[SIG] Missing proof");
    return false;
  }
  const char* sigB64 = doc["proof"]["jws"] | "";
  DynamicJsonDocument tmp(doc);
  tmp.remove("proof");
  String canonical;
  canonicalize(tmp.as<JsonVariant>(), canonical);

  uint8_t sig[64];
  size_t sigLen = decodeBase64Url(sigB64, sig);
  if (sigLen != 64) return false;

  BIO* bio = BIO_new_mem_buf((void*)issuerPubKeyPem, -1);
  EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pkey) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) { EVP_PKEY_free(pkey); return false; }
  bool ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
            EVP_DigestVerify(ctx, sig, sigLen,
                              (const uint8_t*)canonical.c_str(),
                              canonical.length()) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}
#endif

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
      request->send(200, "text/plain", "✅ VC deleted. Restarting...");
      delay(2000);
      ESP.restart();
    } else {
      request->send(404, "text/plain", "❌ No VC file found");
    }
  });

  server.begin();
}

void loop() {
  if (SPIFFS.exists("/vc.json") && !onWiFi) {
    delay(5000);
    WiFi.disconnect();

    Serial.println("\n[INFO] Found /vc.json. Connecting to WiFi...");
    WiFi.mode(WIFI_STA);
    WiFi.begin(staSSID, staPassword);

    int retries = 0;
    while (WiFi.status() != WL_CONNECTED && retries < 20) {
      delay(500);
      Serial.print(".");
      retries++;
    }

    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("\n[CONNECTED] IP: " + WiFi.localIP().toString());
      onWiFi = true;
      verifyVC();
      Serial.println("[INFO] You can delete the VC via: http://" + WiFi.localIP().toString() + "/delete");
    } else {
      Serial.println("\n[ERROR] Failed to connect to WiFi.");
    }
  }

  delay(1000);
}

void handleUpload(AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final) {
  static File file;
  if (index == 0) {
    Serial.printf("[UPLOAD] Start: %s\n", filename.c_str());
    file = SPIFFS.open("/vc.json", FILE_WRITE);
  }
  if (file) {
    file.write(data, len);
  }
  if (final) {
    Serial.printf("[UPLOAD] Done: %s (%u bytes)\n", filename.c_str(), (index + len));
    file.close();
  }
}

void verifyVC() {
  File file = SPIFFS.open("/vc.json", FILE_READ);
  if (!file) {
    Serial.println("[ERROR] Failed to open VC file");
    return;
  }

  String rawVC = file.readString();
  file.close();

  int vcStart = rawVC.indexOf("\"vc\":");
  if (vcStart == -1) {
    Serial.println("[ERROR] 'vc' field not found");
    return;
  }

  String vcOnly = rawVC.substring(vcStart + 5);
  vcOnly.trim();
  int braceStart = vcOnly.indexOf('{');
  if (braceStart == -1) {
    Serial.println("[ERROR] VC not a JSON object");
    return;
  }
  vcOnly = vcOnly.substring(braceStart);
  int bracketCount = 0;
  int endIdx = 0;
  for (int i = 0; i < vcOnly.length(); i++) {
    if (vcOnly[i] == '{') bracketCount++;
    else if (vcOnly[i] == '}') bracketCount--;
    if (bracketCount == 0) {
      endIdx = i + 1;
      break;
    }
  }
  vcOnly = vcOnly.substring(0, endIdx);

  DynamicJsonDocument doc(2048);
  DeserializationError err = deserializeJson(doc, vcOnly);
  if (err) {
    Serial.println("[ERROR] JSON parse failed");
    return;
  }
  const char* fwHash = doc["credentialSubject"]["firmwareHash"] | "";
#if VERIFY_SIGNATURE
  if (verifySignature(doc)) {
    Serial.println("[SIG] Signature valid");
  } else {
    Serial.println("[SIG] Signature invalid");
  }
#endif

  String vpPayload = "{"
    "\"vp\":{"
      "\"@context\": [\"https://www.w3.org/2018/credentials/v1\"],"
      "\"type\": [\"VerifiablePresentation\"],"
      "\"holder\": \"did:local:esp32-device\","
      "\"verifiableCredential\": [" + vcOnly + "]"
    "}"
  "}";

  Serial.println("[DEBUG] VP Payload:");
  Serial.println(vpPayload);

  HTTPClient http;
  http.begin(verificationURL);
  http.addHeader("Content-Type", "application/json");

  int httpCode = http.POST(vpPayload);
  Serial.printf("[VERIFY] HTTP Status: %d\n", httpCode);

  if (httpCode > 0) {
    String response = http.getString();
    Serial.println("[VERIFY] Response: " + response);
  } else {
    Serial.println("[VERIFY] Error: " + http.errorToString(httpCode));
  }

  http.end();

  verifyFirmwareFile(firmwareFile, fwHash);
}

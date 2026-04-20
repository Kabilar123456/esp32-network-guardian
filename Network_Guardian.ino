/*
 * ESP32 Network Guardian v3.1
 * - Detects Evil Twin / Rogue APs
 * - ngrok tunnel for remote dashboard
 * - Block = Deauth burst + Broadcast warning
 * - Email admin with live dashboard link
 *
 * FIXED: All Unicode chars replaced with HTML entities
 */

#include <WiFi.h>
#include <WebServer.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ESP_Mail_Client.h>
#include <ArduinoJson.h>
#include <vector>
#include "esp_wifi.h"
#include "esp_wifi_types.h"

// ==========================================================
//   CONFIGURE THESE BEFORE FLASHING
// ==========================================================


#define WIFI_SSID        "YOUR_WIFI_SSID"
#define WIFI_PASSWORD    "YOUR_WIFI_PASSWORD"
#define TRUSTED_SSID     "trusted SSID"
uint8_t TRUSTED_BSSID[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Your trusted AP MAC

#define SMTP_HOST        "smtp.gmail.com"
#define SMTP_PORT        465
#define SENDER_EMAIL     "your_gmail@gmail.com"
#define SENDER_NAME      "ESP32 Guardian"
#define SENDER_APP_PASS  "your_gmail_app_password"
#define RECIPIENT_EMAIL  "your_email@example.com"
#define RECIPIENT_NAME   "Your Name"
#define DASH_USER        "admin"
#define DASH_PASS        "your_dashboard_password"

#define SCAN_INTERVAL_MS    20000
#define EMAIL_COOLDOWN_MS   3600000
#define DEAUTH_PACKETS      120
#define BROADCAST_DURATION  30000
// ==========================================================

enum ThreatLevel { SAFE, SUSPICIOUS, EVIL_TWIN, ROGUE_AP };
enum BlockStatus  { NOT_BLOCKED, BLOCKING, BLOCKED };

struct APReport {
  String      ssid;
  String      bssidStr;
  uint8_t     bssid[6];
  int         rssi;
  int         channel;
  ThreatLevel threat;
  BlockStatus blockStatus;
  String      reason;
  String      detectedAt;
  int         deauthSent;
  bool        broadcastDone;
};

WebServer   server(80);
SMTPSession smtp;

std::vector<APReport> threatList;
std::vector<APReport> allNetworks;

String espIP         = "";
String ngrokURL = ""; // Your ngrok URL here
bool   emailEnabled  = false;
bool   firstAlert    = true;
unsigned long lastEmailSent = 0;
unsigned long lastScan      = 0;
int    totalScans    = 0;

// ----------------------------------------------------------
String uptimeStr() {
  unsigned long s = millis() / 1000;
  char b[16];
  snprintf(b, sizeof(b), "%02lu:%02lu:%02lu", s/3600, (s%3600)/60, s%60);
  return String(b);
}

int levenshtein(const String& a, const String& b) {
  int la=a.length(), lb=b.length();
  std::vector<std::vector<int>> dp(la+1, std::vector<int>(lb+1,0));
  for(int i=0;i<=la;i++) dp[i][0]=i;
  for(int j=0;j<=lb;j++) dp[0][j]=j;
  for(int i=1;i<=la;i++)
    for(int j=1;j<=lb;j++)
      dp[i][j] = (tolower(a[i-1])==tolower(b[j-1]))
                 ? dp[i-1][j-1]
                 : 1+min(dp[i-1][j], min(dp[i][j-1], dp[i-1][j-1]));
  return dp[la][lb];
}

bool   macMatch(uint8_t* a, uint8_t* b) { return memcmp(a,b,6)==0; }
String macToStr(uint8_t* m) {
  char b[18];
  snprintf(b,sizeof(b),"%02X:%02X:%02X:%02X:%02X:%02X",
           m[0],m[1],m[2],m[3],m[4],m[5]);
  return String(b);
}

ThreatLevel assessThreat(const String& ssid, uint8_t* bssid, int rssi, String& reason) {
  if(ssid.equalsIgnoreCase(TRUSTED_SSID)) {
    if(!macMatch(bssid,TRUSTED_BSSID)) {
      reason = "Exact SSID match - different MAC (Classic Evil Twin attack)";
      return EVIL_TWIN;
    }
    reason = "Verified trusted AP"; return SAFE;
  }
  int d = levenshtein(ssid, String(TRUSTED_SSID));
  if(d>=1 && d<=3) {
    reason = "SSID typo-squatting trusted network (edit dist="+String(d)+")";
    return (rssi>=-65) ? EVIL_TWIN : SUSPICIOUS;
  }
  if(macMatch(bssid,TRUSTED_BSSID)) {
    reason = "MAC matches trusted AP but SSID differs - MAC spoofing";
    return ROGUE_AP;
  }
  return SAFE;
}

int findThreat(const String& bssidStr) {
  for(int i=0;i<(int)threatList.size();i++)
    if(threatList[i].bssidStr==bssidStr) return i;
  return -1;
}

// ----------------------------------------------------------
//  BLOCK ACTION 1: DEAUTH BURST
// ----------------------------------------------------------
void sendDeauth(uint8_t* bssid, int channel) {
  Serial.printf("   Sending %d deauth packets to %s CH%d\n",
                DEAUTH_PACKETS, macToStr(bssid).c_str(), channel);
  uint8_t frame[26] = {
    0xC0,0x00,
    0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
    bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
    0x00,0x00,
    0x03,0x00
  };
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  delay(20);
  for(int i=0;i<DEAUTH_PACKETS;i++) {
    esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
    delay(8);
  }
  Serial.println("   Deauth burst complete.");
}

// ----------------------------------------------------------
//  BLOCK ACTION 2: BROADCAST WARNING AP
// ----------------------------------------------------------
void broadcastWarning(const String& rogueSSID, int rogueChannel) {
  Serial.println("   Broadcasting warning AP to nearby devices...");
  String warnSSID = "FAKE AP: " + rogueSSID + " - DO NOT CONNECT";
  if(warnSSID.length() > 32) warnSSID = "FAKE AP DETECTED - STAY AWAY";

  WiFi.softAP(warnSSID.c_str(), NULL, rogueChannel, 0);
  Serial.println("   Warning AP: \"" + warnSSID + "\" on CH" + String(rogueChannel));

  unsigned long start = millis();
  while(millis()-start < BROADCAST_DURATION) {
    server.handleClient();
    delay(500);
  }

  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  delay(500);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int t=0;
  while(WiFi.status()!=WL_CONNECTED && t<20){ delay(500); t++; }
  Serial.println("   Warning broadcast ended. Reconnected.");
}

// ----------------------------------------------------------
//  COMBINED BLOCK
// ----------------------------------------------------------
void executeBlock(APReport& ap) {
  ap.blockStatus = BLOCKING;
  Serial.println("\nEXECUTING BLOCK: " + ap.ssid + " | " + ap.bssidStr);
  sendDeauth(ap.bssid, ap.channel);
  ap.deauthSent += DEAUTH_PACKETS;
  broadcastWarning(ap.ssid, ap.channel);
  ap.broadcastDone = true;
  sendDeauth(ap.bssid, ap.channel);
  ap.deauthSent += DEAUTH_PACKETS;
  ap.blockStatus = BLOCKED;
  Serial.println("BLOCK COMPLETE: " + ap.bssidStr +
                 " | " + String(ap.deauthSent) + " deauth packets total");
}

// ----------------------------------------------------------
//  SMTP CALLBACK
// ----------------------------------------------------------
void smtpCallback(SMTP_Status s) {
  Serial.println(s.success() ? "   Email sent!" : "   Email failed.");
}

// ----------------------------------------------------------
//  SEND ALERT EMAIL
// ----------------------------------------------------------
void sendAlertEmail(const std::vector<APReport>& threats) {
  if(!emailEnabled) { Serial.println("   No WiFi - email skipped."); return; }
  if(!firstAlert && millis()-lastEmailSent < EMAIL_COOLDOWN_MS) {
    Serial.println("   Email cooldown active."); return;
  }
  firstAlert = false;

  String dashLink = (ngrokURL.length()>0 ? ngrokURL : "http://"+espIP) + "/";

  ESP_Mail_Session session;
  session.server.host_name = SMTP_HOST;
  session.server.port      = SMTP_PORT;
  session.login.email      = SENDER_EMAIL;
  session.login.password   = SENDER_APP_PASS;

  String html = "<!DOCTYPE html><html><body style=\"margin:0;padding:0;"
    "background:#080c18;font-family:Arial,sans-serif;\">"
    "<div style=\"max-width:640px;margin:20px auto;background:#0d1526;"
    "border:1px solid #1e3a5f;border-radius:12px;overflow:hidden;\">"

    "<div style=\"background:linear-gradient(135deg,#8b0000,#cc0000);"
    "padding:28px;text-align:center;\">"
    "<div style=\"font-size:48px;margin-bottom:8px;\">&#x1F6A8;</div>"
    "<h1 style=\"color:#fff;margin:0;font-size:24px;letter-spacing:3px;\">"
    "ROGUE AP DETECTED</h1>"
    "<p style=\"color:#ffaaaa;margin:8px 0 0;font-size:13px;\">"
    "ESP32 NETWORK GUARDIAN &mdash; SECURITY ALERT</p>"
    "</div>"

    "<div style=\"padding:28px;\">"
    "<div style=\"background:#060b14;border:1px solid #cc000044;"
    "border-radius:8px;padding:16px;margin-bottom:20px;\">"
    "<p style=\"color:#ff6666;margin:0;font-size:14px;line-height:1.7;\">"
    "An attacker is broadcasting a fake <strong style=\"color:#ff4444;\">";
  html += String(TRUSTED_SSID);
  html += "</strong> access point nearby.<br>"
    "Users may unknowingly connect and expose their credentials.<br>"
    "<strong style=\"color:#ffbb00;\">Immediate action required.</strong>"
    "</p></div>"

    "<table style=\"width:100%;border-collapse:collapse;font-size:13px;"
    "margin-bottom:24px;\">"
    "<tr style=\"background:#060b14;\">"
    "<th style=\"padding:11px 14px;text-align:left;color:#5a7a9a;"
    "border-bottom:1px solid #1e3a5f;font-size:11px;\">TYPE</th>"
    "<th style=\"padding:11px 14px;text-align:left;color:#5a7a9a;"
    "border-bottom:1px solid #1e3a5f;font-size:11px;\">SSID</th>"
    "<th style=\"padding:11px 14px;text-align:left;color:#5a7a9a;"
    "border-bottom:1px solid #1e3a5f;font-size:11px;\">MAC</th>"
    "<th style=\"padding:11px 14px;text-align:left;color:#5a7a9a;"
    "border-bottom:1px solid #1e3a5f;font-size:11px;\">SIGNAL</th>"
    "</tr>";

  for(int i=0;i<(int)threats.size();i++) {
    const APReport& r = threats[i];
    String badge;
    if(r.threat==EVIL_TWIN)  badge="&#x1F6A8; EVIL TWIN";
    else if(r.threat==ROGUE_AP) badge="&#x1F534; ROGUE AP";
    else badge="&#x1F7E1; SUSPICIOUS";
    String bg = (i%2==0) ? "#0d1018" : "#0a0d14";

    html += "<tr style=\"background:"+bg+";\">"
      "<td style=\"padding:11px 14px;color:#ff4444;font-weight:bold;\">"+badge+"</td>"
      "<td style=\"padding:11px 14px;color:#00ccff;font-weight:bold;\">"+r.ssid+"</td>"
      "<td style=\"padding:11px 14px;color:#5a9aaa;font-size:11px;\">"+r.bssidStr+"</td>"
      "<td style=\"padding:11px 14px;color:#5a7a9a;\">"+String(r.rssi)+" dBm</td>"
      "</tr>"
      "<tr style=\"background:"+bg+";\">"
      "<td colspan=\"4\" style=\"padding:3px 14px 12px;"
      "color:#3a6a4a;font-size:12px;\">&#x2937; "+r.reason+"</td></tr>";
  }

  html += "</table>"
    "<div style=\"text-align:center;margin:28px 0 20px;\">"
    "<a href=\"" + dashLink + "\" target=\"_blank\" "
    "style=\"display:inline-block;background:linear-gradient(135deg,#cc0000,#8b0000);"
    "color:#fff;text-decoration:none;padding:16px 36px;border-radius:8px;"
    "font-size:16px;font-weight:bold;letter-spacing:2px;\">"
    "&#x1F6E1; OPEN SECURITY DASHBOARD</a>"
    "<p style=\"margin-top:10px;font-size:12px;color:#3a5a7a;\">"
    "Login and click BLOCK to neutralize the rogue AP</p>"
    "</div>"

    "<div style=\"background:#060b14;border:1px solid #1e3a5f;"
    "border-radius:6px;padding:14px;font-size:12px;color:#3a5a7a;line-height:2;\">"
    "Dashboard: <span style=\"color:#00aaff;\">"+dashLink+"</span><br>"
    "Login: <span style=\"color:#00ff88;\">"+String(DASH_USER)+"</span>"
    " / (your configured password)<br>"
    "Detected at uptime: <span style=\"color:#ffbb00;\">"+uptimeStr()+"</span><br>"
    "Block action: deauth burst + 30s broadcast warning AP"
    "</div></div>"

    "<div style=\"background:#060b14;padding:12px;text-align:center;"
    "font-size:11px;color:#2a4a6a;letter-spacing:1px;\">"
    "ESP32 NETWORK GUARDIAN v3.1 &mdash; AUTOMATED ALERT"
    "</div></div></body></html>";

  SMTP_Message msg;
  msg.sender.name  = SENDER_NAME;
  msg.sender.email = SENDER_EMAIL;
  msg.subject = String("[SECURITY ALERT] Evil Twin attacking \"") + TRUSTED_SSID + "\" - Action Required";
  msg.addRecipient(RECIPIENT_NAME, RECIPIENT_EMAIL);
  msg.html.content = html.c_str();
  msg.html.charSet = "utf-8";
  msg.priority = esp_mail_smtp_priority_high;

  smtp.debug(0);
  smtp.callback(smtpCallback);
  if(!smtp.connect(&session)) {
    Serial.println("SMTP err: "+smtp.errorReason()); return;
  }
  if(MailClient.sendMail(&smtp,&msg)) lastEmailSent=millis();
  smtp.closeSession();
}

// ----------------------------------------------------------
//  DASHBOARD HTML  (all Unicode as HTML entities)
// ----------------------------------------------------------
String buildDashboard() {

  // Count blocked
  int blocked=0;
  for(auto& t:threatList)
    if(t.blockStatus==BLOCKED||t.blockStatus==BLOCKING) blocked++;

  String h =
    "<!DOCTYPE html><html lang=\"en\"><head>"
    "<meta charset=\"UTF-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>Network Guardian</title>"
    "<style>"
    ":root{"
      "--bg:#07090f;--surf:#0d1220;--bdr:#1a2f4a;"
      "--grn:#00ff99;--red:#ff3355;--ylw:#ffcc00;--blu:#00aaff;--orn:#ff8800;"
      "--txt:#d0dcea;--mut:#3a5a7a;"
    "}"
    "*{margin:0;padding:0;box-sizing:border-box;}"
    "body{background:var(--bg);color:var(--txt);font-family:'Courier New',monospace;"
      "min-height:100vh;}"
    "body::before{content:'';position:fixed;inset:0;"
      "background-image:linear-gradient(var(--bdr) 1px,transparent 1px),"
        "linear-gradient(90deg,var(--bdr) 1px,transparent 1px);"
      "background-size:40px 40px;opacity:0.25;pointer-events:none;z-index:0;}"
    ".wrap{position:relative;z-index:1;max-width:1140px;margin:0 auto;padding:24px 20px;}"
    ".topbar{display:flex;align-items:center;justify-content:space-between;"
      "padding-bottom:20px;border-bottom:1px solid var(--bdr);margin-bottom:24px;}"
    ".brand{display:flex;align-items:center;gap:14px;}"
    ".brand-icon{width:44px;height:44px;background:linear-gradient(135deg,var(--red),#8b0000);"
      "border-radius:10px;display:flex;align-items:center;justify-content:center;"
      "font-size:22px;box-shadow:0 0 20px rgba(255,51,85,0.3);}"
    ".brand h1{font-size:18px;color:var(--red);letter-spacing:3px;}"
    ".brand p{font-size:10px;color:var(--mut);letter-spacing:2px;margin-top:2px;}"
    ".dot{width:8px;height:8px;border-radius:50%;background:var(--grn);"
      "display:inline-block;margin-right:6px;"
      "animation:blink 1.5s infinite;}"
    "@keyframes blink{"
      "0%,100%{box-shadow:0 0 0 0 rgba(0,255,153,0.4);}"
      "50%{box-shadow:0 0 0 6px rgba(0,255,153,0);}}"
    ".live{font-size:11px;color:var(--grn);letter-spacing:2px;"
      "border:1px solid rgba(0,255,153,0.3);padding:5px 14px;border-radius:20px;"
      "background:rgba(0,255,153,0.05);}"
    ".stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));"
      "gap:12px;margin-bottom:28px;}"
    ".stat{background:var(--surf);border:1px solid var(--bdr);border-radius:10px;"
      "padding:18px 14px;text-align:center;position:relative;overflow:hidden;}"
    ".stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;}"
    ".sr::before{background:var(--red);}.sg::before{background:var(--grn);}"
    ".sy::before{background:var(--ylw);}.sb::before{background:var(--blu);}"
    ".so::before{background:var(--orn);}"
    ".sv{font-size:26px;font-weight:bold;line-height:1;}"
    ".sl{font-size:10px;color:var(--mut);margin-top:6px;letter-spacing:2px;}"
    ".cr{color:var(--red);}.cg{color:var(--grn);}.cy{color:var(--ylw);}"
    ".cb{color:var(--blu);}.co{color:var(--orn);}"
    ".stitle{font-size:10px;letter-spacing:3px;color:var(--mut);"
      "margin-bottom:12px;display:flex;align-items:center;gap:10px;}"
    ".stitle::after{content:'';flex:1;height:1px;background:var(--bdr);}"
    ".tbl-wrap{overflow-x:auto;margin-bottom:28px;}"
    "table{width:100%;border-collapse:collapse;font-size:12px;}"
    "th{padding:10px 14px;text-align:left;background:var(--surf);"
      "color:var(--mut);letter-spacing:2px;font-size:10px;border-bottom:1px solid var(--bdr);}"
    "td{padding:12px 14px;border-bottom:1px solid rgba(26,47,74,0.5);vertical-align:middle;}"
    "tr:hover td{background:rgba(13,18,32,0.8);}"
    ".badge{display:inline-block;padding:3px 9px;border-radius:4px;"
      "font-size:10px;font-weight:bold;letter-spacing:1px;}"
    ".be{background:rgba(255,51,85,0.1);color:var(--red);border:1px solid rgba(255,51,85,0.3);}"
    ".br{background:rgba(255,136,0,0.1);color:var(--orn);border:1px solid rgba(255,136,0,0.3);}"
    ".bs{background:rgba(255,204,0,0.1);color:var(--ylw);border:1px solid rgba(255,204,0,0.3);}"
    ".bk{background:rgba(0,255,153,0.1);color:var(--grn);border:1px solid rgba(0,255,153,0.3);}"
    ".btn{padding:7px 16px;border-radius:6px;border:none;cursor:pointer;"
      "font-family:'Courier New',monospace;font-size:11px;font-weight:bold;"
      "letter-spacing:1px;transition:all 0.2s;text-transform:uppercase;}"
    ".btn-blk{background:linear-gradient(135deg,var(--red),#8b0000);color:#fff;}"
    ".btn-blk:hover{box-shadow:0 0 16px rgba(255,51,85,0.5);transform:translateY(-1px);}"
    ".btn-blk:disabled{background:#111;color:#333;cursor:not-allowed;"
      "transform:none;box-shadow:none;border:1px solid #1a2f4a;}"
    ".btn-ing{background:linear-gradient(135deg,var(--orn),#8b4400)!important;"
      "animation:blink2 0.8s infinite;}"
    "@keyframes blink2{0%,100%{opacity:1;}50%{opacity:0.6;}}"
    ".btn-done{background:rgba(255,51,85,0.05)!important;color:var(--red)!important;"
      "border:1px solid rgba(255,51,85,0.2)!important;font-size:10px!important;}"
    ".log-box{background:#040710;border:1px solid var(--bdr);border-radius:8px;"
      "padding:16px;height:170px;overflow-y:auto;font-size:11px;line-height:2;"
      "scrollbar-width:thin;scrollbar-color:var(--bdr) transparent;}"
    ".log-box::-webkit-scrollbar{width:4px;}"
    ".log-box::-webkit-scrollbar-thumb{background:var(--bdr);}"
    ".lg{color:#2a6a4a;}.lw{color:var(--ylw);}.ld{color:var(--red);}.lo{color:var(--grn);}"
    ".empty{text-align:center;padding:44px;color:var(--mut);font-size:12px;letter-spacing:1px;}"
    ".ssid{color:#e0eeff;font-weight:bold;}"
    ".mac{color:#3a7a9a;font-size:11px;}"
    ".ctrl{display:flex;align-items:center;justify-content:space-between;"
      "margin-bottom:20px;font-size:11px;color:var(--mut);}"
    ".btn-sm{background:var(--surf);border:1px solid var(--bdr);"
      "color:var(--blu);padding:6px 16px;border-radius:6px;cursor:pointer;"
      "font-family:'Courier New',monospace;font-size:11px;letter-spacing:1px;}"
    ".btn-sm:hover{border-color:var(--blu);background:rgba(0,170,255,0.05);}"
    ".inf{font-size:10px;color:var(--mut);}"
    "</style></head><body>"
    "<div class=\"wrap\">"

    // Top bar
    "<div class=\"topbar\">"
      "<div class=\"brand\">"
        "<div class=\"brand-icon\">&#x1F6E1;</div>"
        "<div>"
          "<h1>NETWORK GUARDIAN</h1>"
          "<p>ESP32 EVIL TWIN DETECTION SYSTEM</p>"
        "</div>"
      "</div>"
      "<div class=\"live\"><span class=\"dot\"></span>LIVE MONITOR</div>"
    "</div>"

    // Stats
    "<div class=\"stats\">"
      "<div class=\"stat sb\"><div class=\"sv cb\">" + String(totalScans) + "</div>"
        "<div class=\"sl\">Scans Run</div></div>"
      "<div class=\"stat sr\"><div class=\"sv cr\">" + String(threatList.size()) + "</div>"
        "<div class=\"sl\">Threats Found</div></div>"
      "<div class=\"stat so\"><div class=\"sv co\">" + String(blocked) + "</div>"
        "<div class=\"sl\">Blocked</div></div>"
      "<div class=\"stat sg\"><div class=\"sv cg\">" + String(allNetworks.size()) + "</div>"
        "<div class=\"sl\">APs Visible</div></div>"
      "<div class=\"stat sy\"><div class=\"sv cy\">" + uptimeStr() + "</div>"
        "<div class=\"sl\">Uptime</div></div>"
    "</div>"

    // Controls
    "<div class=\"ctrl\">"
      "<span>Protecting: <b style=\"color:var(--grn)\">" + String(TRUSTED_SSID) + "</b>"
        " &nbsp;|&nbsp; IP: <b style=\"color:var(--blu)\">" + espIP + "</b>"
        " &nbsp;|&nbsp; Last scan: " + uptimeStr() + "</span>"
      "<button class=\"btn-sm\" onclick=\"location.reload()\">&#x27F3; REFRESH</button>"
    "</div>"

    // Threats section
    "<div class=\"stitle\">&#x26A0; Active Threats</div>";

  if(threatList.empty()) {
    h += "<div class=\"empty\">&#x2705; &nbsp;NO THREATS DETECTED &mdash; NETWORK CLEAN</div>";
  } else {
    h += "<div class=\"tbl-wrap\"><table>"
         "<thead><tr>"
           "<th>THREAT TYPE</th><th>SSID</th><th>BSSID (MAC)</th>"
           "<th>SIGNAL</th><th>CH</th><th>DETECTED</th><th>ACTION</th>"
         "</tr></thead><tbody>";

    for(auto& r : threatList) {
      String badge, bc;
      if(r.threat==EVIL_TWIN)  { badge="&#x1F6A8; EVIL TWIN"; bc="be"; }
      else if(r.threat==ROGUE_AP) { badge="&#x1F534; ROGUE AP"; bc="br"; }
      else { badge="&#x1F7E1; SUSPICIOUS"; bc="bs"; }

      h += "<tr>"
           "<td><span class=\"badge "+bc+"\">"+badge+"</span></td>"
           "<td><span class=\"ssid\">"+r.ssid+"</span></td>"
           "<td><span class=\"mac\">"+r.bssidStr+"</span></td>"
           "<td class=\"inf\">"+String(r.rssi)+" dBm</td>"
           "<td>"+String(r.channel)+"</td>"
           "<td class=\"inf\">"+r.detectedAt+"</td>";

      if(r.blockStatus==BLOCKED) {
        h += "<td><button class=\"btn btn-blk btn-done\" disabled>"
             "&#x1F6AB; BLOCKED<br>"
             "<span style=\"font-size:9px;opacity:0.7;\">"+String(r.deauthSent)+" pkts sent</span>"
             "</button></td>";
      } else if(r.blockStatus==BLOCKING) {
        h += "<td><button class=\"btn btn-blk btn-ing\" disabled>"
             "&#x26A1; BLOCKING...</button></td>";
      } else {
        h += "<td><button class=\"btn btn-blk\" "
             "onclick=\"doBlock('"+r.bssidStr+"',"+String(r.channel)+")\""
             ">&#x1F512; BLOCK</button></td>";
      }
      h += "</tr><tr>"
           "<td colspan=\"7\" style=\"padding:3px 14px 12px;"
           "font-size:10px;color:#2a5a3a;\">"
           "&#x2937; "+r.reason;
      if(r.broadcastDone)
        h += " &nbsp;|&nbsp; <span style=\"color:#00ff99;\">&#x2705; Broadcast warning sent</span>";
      h += "</td></tr>";
    }
    h += "</tbody></table></div>";
  }

  // All networks
  h += "<div class=\"stitle\" style=\"margin-top:4px;\">&#x1F4E1; All Visible Networks</div>"
       "<div class=\"tbl-wrap\"><table>"
       "<thead><tr>"
         "<th>STATUS</th><th>SSID</th><th>BSSID</th><th>SIGNAL</th><th>CH</th>"
       "</tr></thead><tbody>";

  for(auto& r : allNetworks) {
    String badge, bc;
    if(r.threat==EVIL_TWIN)   { badge="&#x1F6A8; EVIL TWIN"; bc="be"; }
    else if(r.threat==ROGUE_AP)  { badge="&#x1F534; ROGUE AP";  bc="br"; }
    else if(r.threat==SUSPICIOUS){ badge="&#x1F7E1; SUSPICIOUS"; bc="bs"; }
    else                         { badge="&#x2705; SAFE";        bc="bk"; }

    h += "<tr>"
         "<td><span class=\"badge "+bc+"\">"+badge+"</span></td>"
         "<td><span class=\"ssid\">"+(r.ssid.length()?r.ssid:"&lt;hidden&gt;")+"</span></td>"
         "<td><span class=\"mac\">"+r.bssidStr+"</span></td>"
         "<td class=\"inf\">"+String(r.rssi)+" dBm</td>"
         "<td>"+String(r.channel)+"</td>"
         "</tr>";
  }
  h += "</tbody></table></div>";

  // Log
  h += "<div class=\"stitle\">&#x1F4CB; Event Log</div>"
       "<div class=\"log-box\">"
       "<div class=\"lo\">["+uptimeStr()+"] System active | Scans: "+String(totalScans)+"</div>";

  for(auto& t : threatList) {
    String cls = (t.threat==EVIL_TWIN||t.threat==ROGUE_AP) ? "ld" : "lw";
    h += "<div class=\""+cls+"\">["+t.detectedAt+"] THREAT: "+t.ssid+" @ "+t.bssidStr+"</div>";
    if(t.blockStatus==BLOCKED) {
      h += "<div class=\"lo\">["+t.detectedAt+"] BLOCKED: deauth x"
           +String(t.deauthSent)+" + broadcast warning sent</div>";
    }
  }

  h += "</div>" // log-box

  // JS
       "<script>"
       "function doBlock(bssid,ch){"
         "if(!confirm('BLOCK ' + bssid + ' on CH' + ch + '?\\n\\n'"
           "+'This will:\\n'"
           "+'  1. Send deauth packets (kick all clients)\\n'"
           "+'  2. Broadcast 30s WARNING AP visible to\\n'"
           "+'     all nearby WiFi devices\\n\\n'"
           "+'Confirm?')) return;"
         "var btn=event.target;"
         "btn.textContent='Blocking...';"
         "btn.className='btn btn-blk btn-ing';"
         "btn.disabled=true;"
         "fetch('/block?bssid='+encodeURIComponent(bssid)+'&channel='+ch)"
           ".then(r=>r.json())"
           ".then(d=>{"
             "if(d.success){setTimeout(()=>location.reload(),2000);}"
             "else{alert('Error: '+(d.error||'unknown'));location.reload();}"
           "})"
           ".catch(()=>{"
             "alert('ESP32 is broadcasting warning. Refresh in 35 seconds.');"
           "});"
       "}"
       "setTimeout(()=>location.reload(),30000);"
       "</script>"
       "</div></body></html>";

  return h;
}

// ----------------------------------------------------------
//  WEB HANDLERS
// ----------------------------------------------------------
void handleRoot() {
  if(!server.authenticate(DASH_USER,DASH_PASS)) return server.requestAuthentication();
  server.send(200,"text/html",buildDashboard());
}

void handleBlock() {
  if(!server.authenticate(DASH_USER,DASH_PASS)) return server.requestAuthentication();
  if(!server.hasArg("bssid")||!server.hasArg("channel")) {
    server.send(400,"application/json","{\"success\":false,\"error\":\"Missing params\"}");
    return;
  }
  String bssidStr = server.arg("bssid");
  int channel     = server.arg("channel").toInt();
  int idx = findThreat(bssidStr);
  if(idx<0) {
    server.send(404,"application/json","{\"success\":false,\"error\":\"AP not found\"}");
    return;
  }
  // Respond BEFORE executing (block takes ~35s, browser would time out)
  server.send(200,"application/json","{\"success\":true}");
  executeBlock(threatList[idx]);
}

void handleStatus() {
  int blocked=0;
  for(auto& t:threatList) if(t.blockStatus==BLOCKED) blocked++;
  server.send(200,"application/json",
    "{\"scans\":"+String(totalScans)+
    ",\"threats\":"+String(threatList.size())+
    ",\"blocked\":"+String(blocked)+
    ",\"uptime\":\""+uptimeStr()+"\"}");
}

// ----------------------------------------------------------
//  WIFI
// ----------------------------------------------------------
void connectWiFi() {
  Serial.printf("\nConnecting to %s", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int t=0;
  while(WiFi.status()!=WL_CONNECTED && t<30){ delay(500); Serial.print("."); t++; }
  if(WiFi.status()==WL_CONNECTED) {
    espIP = WiFi.localIP().toString();
    Serial.println("\nWiFi connected! IP: "+espIP);
    emailEnabled = true;
  } else {
    Serial.println("\nWiFi failed - email disabled.");
    emailEnabled = false;
  }
}

void printNgrokInstructions() {
  Serial.println("\n+------------------------------------------------+");
  Serial.println("|  NGROK SETUP - run on any PC on same network:  |");
  Serial.println("|                                                  |");
  Serial.println("|  1. Download: https://ngrok.com/download         |");
  Serial.println("|  2. ngrok authtoken YOUR_TOKEN                   |");
  Serial.printf( "|  3. ngrok http %s:80              |\n", espIP.c_str());
  Serial.println("|  4. Copy the https://xxxx.ngrok-free.app URL     |");
  Serial.println("+--------------------------------------------------+");
  Serial.println("Local dashboard: http://"+espIP+"/");
  Serial.println("Login: "+String(DASH_USER)+" / "+String(DASH_PASS));
}

// ----------------------------------------------------------
//  MAIN SCAN
// ----------------------------------------------------------
void runScan() {
  Serial.println("\n-------------------------------------");
  Serial.printf("Scan #%d starting...\n", totalScans+1);

  int n = WiFi.scanNetworks(false,true);
  totalScans++;
  allNetworks.clear();

  if(n<=0) { Serial.println("No networks found."); return; }

  std::vector<APReport> newThreats;
  for(int i=0;i<n;i++) {
    APReport r;
    r.ssid         = WiFi.SSID(i);
    r.bssidStr     = macToStr(WiFi.BSSID(i));
    memcpy(r.bssid, WiFi.BSSID(i), 6);
    r.rssi         = WiFi.RSSI(i);
    r.channel      = WiFi.channel(i);
    r.blockStatus  = NOT_BLOCKED;
    r.deauthSent   = 0;
    r.broadcastDone= false;
    r.detectedAt   = uptimeStr();
    r.threat       = assessThreat(r.ssid, WiFi.BSSID(i), r.rssi, r.reason);
    allNetworks.push_back(r);

    if(r.threat!=SAFE && findThreat(r.bssidStr)<0) {
      threatList.push_back(r);
      newThreats.push_back(r);
      Serial.println("THREAT: "+r.ssid+" | "+r.bssidStr);
      Serial.println("  -> "+r.reason);
    }
  }

  Serial.printf("%d APs found | %d total threats | %d new\n",
                n, (int)threatList.size(), (int)newThreats.size());

  if(!newThreats.empty()) {
    Serial.println("Sending email alert...");
    sendAlertEmail(newThreats);
  }
  WiFi.scanDelete();
}

// ----------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(600);
  Serial.println("\n+==========================================+");
  Serial.println("|   ESP32 NETWORK GUARDIAN v3.1            |");
  Serial.println("|   Evil Twin Detector + Deauth + Broadcast |");
  Serial.println("+==========================================+");
  Serial.println("Protecting SSID: " + String(TRUSTED_SSID));

  connectWiFi();

  server.on("/",       handleRoot);
  server.on("/block",  handleBlock);
  server.on("/status", handleStatus);
  server.begin();

  printNgrokInstructions();
}

void loop() {
  server.handleClient();
  if(WiFi.status()!=WL_CONNECTED) connectWiFi();
  if(millis()-lastScan >= SCAN_INTERVAL_MS) {
    lastScan = millis();
    runScan();
  }
}

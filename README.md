# esp32-network-guardian
ESP32-based Evil Twin / Rogue AP detector with email alerts and web dashboard
# 🛡️ ESP32 Network Guardian v3.1
> Real-time Evil Twin & Rogue Access Point Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-ESP32-blue.svg)](https://www.espressif.com/)
[![IDE](https://img.shields.io/badge/IDE-Arduino%202.3.8-teal.svg)](https://www.arduino.cc/)

---

## 📋 Table of Contents
- [Project Overview](#-project-overview)
- [How It Works](#-how-it-works)
- [Technical Architecture](#-technical-architecture)
- [Detection Algorithms](#-detection-algorithms)
- [Security Features](#-security-features)
- [Complete Beginner Setup Guide](#-complete-beginner-setup-guide)
- [Configuration Reference](#-configuration-reference)
- [Dashboard](#-dashboard)
- [Legal Notice](#-legal-notice)
- [Author](#-author)

---

## 📌 Project Overview

ESP32 Network Guardian is an embedded cybersecurity tool that continuously monitors the surrounding WiFi environment to detect **Evil Twin attacks**, **Rogue Access Points**, and **MAC spoofing**. When a threat is detected, it automatically:

- Sends an **email alert** to the administrator
- Displays threat details on a **live web dashboard**
- Allows the admin to **block** the rogue AP remotely

**Built for:** Network security monitoring, university/campus environments, cybersecurity research and demonstrations.

---

## 🔍 How It Works

```
ESP32 scans WiFi every 20s
        │
        ▼
Compare each AP against trusted SSID + BSSID
        │
   ┌────┴────┐
   │         │
Threat?    Safe
   │
   ▼
Classify threat type
(Evil Twin / Rogue AP / Suspicious)
   │
   ▼
Add to dashboard + Send email alert
   │
   ▼
Admin clicks BLOCK on dashboard
   │
   ▼
Deauth burst + Broadcast warning AP
```

---

## 🏗️ Technical Architecture

| Component | Technology |
|-----------|-----------|
| Microcontroller | ESP32 (dual-core, 240MHz) |
| Language | C++ (Arduino framework) |
| Web Server | ESP32 WebServer on port 80 |
| Email | SMTP over SSL (port 465) via ESP_Mail_Client |
| Remote Access | ngrok reverse tunnel |
| Data Format | JSON (ArduinoJson library) |
| Authentication | HTTP Basic Auth on dashboard |

### Libraries Used
| Library | Purpose |
|---------|---------|
| `WiFi.h` | WiFi scanning and connection |
| `WebServer.h` | Hosts the dashboard |
| `ESP_Mail_Client.h` | Sends SMTP email alerts |
| `ArduinoJson.h` | JSON API responses |
| `esp_wifi.h` | Raw 802.11 frame injection |

---

## 🧠 Detection Algorithms

### 1. Evil Twin Detection
Checks if any scanned AP has the **exact same SSID** as the trusted network but a **different MAC address (BSSID)**. A different MAC on the same network name is the classic Evil Twin signature.

```
Scanned SSID == Trusted SSID  →  YES
Scanned BSSID == Trusted BSSID →  NO
Result: EVIL TWIN ✗
```

### 2. Typo-Squatting Detection (Levenshtein Distance)
Uses the **Levenshtein distance algorithm** to catch SSIDs that are slight variations of the trusted network name (e.g., `edur0am`, `eduroaam`, `Eduroam`). Any SSID within edit distance 1–3 is flagged.

```cpp
// Example
levenshtein("eduroam", "edur0am") = 1  → SUSPICIOUS/EVIL TWIN
levenshtein("eduroam", "eduroaam") = 1 → SUSPICIOUS/EVIL TWIN
```

If signal strength is stronger than -65 dBm (close proximity), it is escalated to EVIL TWIN; otherwise SUSPICIOUS.

### 3. MAC Spoofing Detection
If a scanned AP uses the **exact MAC address** of the trusted AP but broadcasts a **different SSID**, it is classified as MAC spoofing / ROGUE AP.

### Threat Classification Table

| Condition | Classification |
|-----------|---------------|
| Same SSID + different MAC | 🚨 EVIL TWIN |
| Similar SSID (edit distance 1–3) + strong signal | 🚨 EVIL TWIN |
| Similar SSID (edit distance 1–3) + weak signal | 🟡 SUSPICIOUS |
| Trusted MAC + different SSID | 🔴 ROGUE AP |
| Everything else | ✅ SAFE |

---

## 🔒 Security Features

- **Dashboard authentication** — HTTP Basic Auth protects the web interface
- **Email cooldown** — Maximum one alert email per hour to prevent spam
- **Block action 1: Deauth burst** — Sends 802.11 deauthentication frames to disconnect clients from the rogue AP
- **Block action 2: Broadcast warning** — Creates a visible warning AP (`FAKE AP: <name> - DO NOT CONNECT`) for 30 seconds so nearby users are alerted
- **ngrok tunnel** — Allows remote dashboard access from anywhere without port forwarding

---

## 🚀 Complete Beginner Setup Guide

If you are new to ESP32 and Arduino, follow every step carefully. This guide will take you from zero to a working project.

---

### What You Need
- 1× ESP32 development board (ESP32S or similar)
- 1× USB cable (to connect ESP32 to your computer)
- A computer with Windows/Mac/Linux
- A Gmail account (for sending alert emails)
- A mobile hotspot or WiFi router

---

### Step 1 — Install Arduino IDE

1. Go to [https://www.arduino.cc/en/software](https://www.arduino.cc/en/software)
2. Download **Arduino IDE 2.3.8** for your operating system
3. Install it like a normal program

---

### Step 2 — Add ESP32 Support to Arduino IDE

Arduino IDE does not support ESP32 by default. You need to add it manually.

1. Open Arduino IDE
2. Go to **File → Preferences**
3. Find the field called **"Additional boards manager URLs"**
4. Paste this URL into that field:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
5. Click **OK**
6. Go to **Tools → Board → Boards Manager**
7. Search for `esp32`
8. Install **"esp32 by Espressif Systems"**
9. Wait for installation to complete

---

### Step 3 — Install Required Libraries

1. Go to **Tools → Manage Libraries**
2. Search and install each of these one by one:
   - `ESP Mail Client` by Mobizt
   - `ArduinoJson` by Benoit Blanchon

---

### Step 4 — Connect ESP32 to Your Computer

1. Connect your ESP32 to your computer using the USB cable
2. Open Arduino IDE
3. Go to **Tools → Board** and select **"ESP32 Dev Module"**
4. Go to **Tools → Port** and select the port your ESP32 is connected to
   - On Windows it will look like `COM3` or `COM4`
   - On Mac/Linux it will look like `/dev/ttyUSB0`

> **Tip:** If you don't see any port, you may need to install the CP2102 or CH340 USB driver for your ESP32 board. Search for your board's chip name + "USB driver" to find it.

---

### Step 5 — Create the Project File

1. Open Arduino IDE
2. Go to **File → New Sketch**
3. Go to **File → Save As** and name it `Network_Guardian`
4. Delete everything in the file
5. Copy and paste the full code from `Network_Guardian.ino` in this repository
6. Save the file

---

### Step 6 — Set Up Gmail App Password

> ⚠️ You **cannot** use your normal Gmail password in this project. Google blocks it for security reasons. You must create a special **App Password**. Follow these steps exactly:

1. Go to your Google Account: [https://myaccount.google.com](https://myaccount.google.com)
2. Click **"Security"** in the left menu
3. Scroll down to find **"2-Step Verification"** and click it
4. Turn ON 2-Step Verification if it is not already on (follow Google's steps)
5. Once 2-Step Verification is ON, go back to **Security**
6. Search for **"App passwords"** at the top of the page or scroll to find it
7. Click **"App passwords"**
8. In the **"App name"** field type: `ESP32 Guardian`
9. Click **"Create"**
10. Google will show you a **16-character password** like: `abcd efgh ijkl mnop`
11. **Copy this password immediately** — Google will never show it again
12. Paste this password into the `SENDER_APP_PASS` field in the code

> This App Password is what the ESP32 uses to log in to Gmail and send emails on your behalf.

---

### Step 7 — Find Your Target WiFi MAC Address

You need the MAC address (BSSID) of the WiFi network you want to protect/monitor.

**On Windows:**
1. Connect your PC to the target WiFi
2. Open Command Prompt (search CMD)
3. Type: `netsh wlan show interfaces`
4. Look for **"BSSID"** — it will look like `EA:06:8B:75:4D:5A`

**On Android:**
1. Go to Settings → WiFi
2. Tap the connected network
3. Look for **"Router MAC"** or **"Gateway MAC"**

Convert the MAC address format for the code:
```
EA:06:8B:75:4D:5A  →  {0xEA, 0x06, 0x8B, 0x75, 0x4D, 0x5A}
```

---

### Step 8 — Fill In Your Configuration

Open the code and find the configuration section at the top. Fill in your details:

```cpp
// The WiFi the ESP32 connects to (your hotspot or router)
#define WIFI_SSID        "YOUR_WIFI_SSID"       // e.g. "MyHotspot"
#define WIFI_PASSWORD    "YOUR_WIFI_PASSWORD"   // e.g. "mypassword123"

// The WiFi network you want to MONITOR and protect
#define TRUSTED_SSID     "trusted SSID"         // e.g. "eduroam"
uint8_t TRUSTED_BSSID[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // MAC from Step 7

// Email settings - DO NOT change SMTP_HOST or SMTP_PORT
#define SMTP_HOST        "smtp.gmail.com"
#define SMTP_PORT        465

// The Gmail account the ESP32 SENDS alerts FROM
#define SENDER_EMAIL     "your_gmail@gmail.com"
#define SENDER_NAME      "ESP32 Guardian"
#define SENDER_APP_PASS  "your_gmail_app_password"  // 16-char password from Step 6

// The email address that RECEIVES the alert
#define RECIPIENT_EMAIL  "your_email@example.com"
#define RECIPIENT_NAME   "Your Name"

// Dashboard login credentials
#define DASH_USER        "admin"
#define DASH_PASS        "your_dashboard_password"
```

> 💡 **Simple explanation:**
> - `WIFI_SSID` / `WIFI_PASSWORD` = the WiFi the ESP32 uses to connect to internet (your hotspot)
> - `TRUSTED_SSID` = the WiFi you want to watch and protect (e.g. your university WiFi)
> - `SENDER_EMAIL` = the Gmail the ESP32 logs into to send you alerts
> - `RECIPIENT_EMAIL` = your email where you receive the alerts

---

### Step 9 — Upload the Code to ESP32

1. In Arduino IDE, click the **Upload button** (right arrow → icon at the top)
2. Wait for it to compile and upload — this takes about 30–60 seconds
3. You will see **"Done uploading"** when it finishes

---

### Step 10 — Find the ESP32 IP Address

1. In Arduino IDE, go to **Tools → Serial Monitor**
2. Set the baud rate to **115200** (bottom right of Serial Monitor)
3. Press the **EN** or **RST** (reset) button on your ESP32
4. You will see output like:
   ```
   ESP32 NETWORK GUARDIAN v3.1
   Connecting to MyHotspot..........
   WiFi connected! IP: 192.0.2.1
   Local dashboard: http://192.0.2.1/
   ```
5. **Write down the IP address** (e.g. `192.0.2.1`)

---

### Step 11 — Set Up ngrok for Remote Access

ngrok creates a public internet link to your ESP32 dashboard so you can access it from anywhere.

1. Go to [https://ngrok.com](https://ngrok.com) and create a free account
2. Download ngrok for your operating system
3. Open your terminal or Command Prompt
4. Run this command to add your auth token (find token in your ngrok dashboard):
   ```
   ngrok authtoken YOUR_TOKEN_HERE
   ```
5. Then run this command using your ESP32 IP from Step 10:
   ```
   ngrok http 192.0.2.1:80
   ```
6. ngrok will show a public URL like:
   ```
   Forwarding  https://abcd-1234.ngrok-free.app -> http://192.0.2.1:80
   ```
7. Copy that `https://` URL and paste it into the code:
   ```cpp
   String ngrokURL = "https://abcd-1234.ngrok-free.app";
   ```
8. Re-upload the code (Step 9)

> Now you can open the dashboard from any device anywhere using that ngrok link.

---

### Step 12 — Open the Dashboard

1. Make sure your PC is on the same WiFi as the ESP32
2. Open a browser and go to: `http://192.0.2.1/` (your ESP32 IP)
3. Enter your dashboard username and password
4. You will see the live monitoring dashboard

---

### ✅ Setup Complete!

The ESP32 will now:
- Scan for nearby WiFi networks every 20 seconds
- Detect any Evil Twin or Rogue AP attacks
- Send you an email alert when a threat is found (max once per hour)
- Let you block threats from the dashboard

---

## ⚙️ Configuration Reference

| Parameter | Description | Default |
|-----------|-------------|---------|
| `WIFI_SSID` | WiFi the ESP32 connects to | — |
| `WIFI_PASSWORD` | Password for above WiFi | — |
| `TRUSTED_SSID` | Network to monitor/protect | — |
| `TRUSTED_BSSID` | MAC address of trusted AP | — |
| `SENDER_EMAIL` | Gmail that sends alerts | — |
| `SENDER_APP_PASS` | Gmail App Password (16 chars) | — |
| `RECIPIENT_EMAIL` | Email that receives alerts | — |
| `DASH_USER` | Dashboard login username | `admin` |
| `DASH_PASS` | Dashboard login password | — |
| `SCAN_INTERVAL_MS` | How often to scan (ms) | `20000` (20s) |
| `EMAIL_COOLDOWN_MS` | Min time between emails (ms) | `3600000` (1hr) |
| `DEAUTH_PACKETS` | Deauth frames per block action | `120` |
| `BROADCAST_DURATION` | Warning AP broadcast time (ms) | `30000` (30s) |

---

## 📊 Dashboard

The web dashboard is accessible at `http://<ESP32_IP>/` and shows:

- **Live threat table** — all detected Evil Twins and Rogue APs
- **All visible networks** — complete WiFi scan results with classification
- **Statistics** — total scans, threats found, blocked count, uptime
- **Event log** — timestamped history of detections and block actions
- **Block button** — one-click to execute deauth + broadcast warning

Dashboard auto-refreshes every 30 seconds.

---

## ⚠️ Legal Notice

This tool is designed for **authorized network security monitoring only**.

- Only use this on networks you **own** or have **explicit written permission** to monitor
- The deauthentication feature transmits raw 802.11 management frames — this may be regulated or illegal in your jurisdiction without authorization
- In the EU and many other countries, unauthorized interference with wireless networks violates computer misuse laws
- The author takes no responsibility for misuse of this tool

**Intended use cases:** Home network protection, authorized penetration testing, academic research, university lab demonstrations.

---

## 👤 Author

**Kabilar Pari**
- 📧 pskabilar1233@gmail.com
- 💼 www.linkedin.com/in/kabilar-pari-79106b307


---

*ESP32 Network Guardian v3.1 — Built for cybersecurity research and education*

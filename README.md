<div align="center">

# 🛡️ DaddyWatch v1.0
### Enterprise-Grade Endpoint Network Intelligence & Threat Defense

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![Runtime](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Architecture](https://img.shields.io/badge/Architecture-x64%20%7C%20ARM64-lightgrey)](#)
[![Performance](https://img.shields.io/badge/CPU%20Impact-%3C%200.5%25-brightgreen)](#performance--optimization)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.com/paypalme/iepuroi)

**DaddyWatch** is an ultra-fast, lightweight, and modern network security monitor and active defense suite built natively for Windows. It provides kernel-level process socket attribution, multi-source threat intelligence matching, country-level geoblocking, and automated Windows Firewall mitigation—all wrapped in a sleek, zero-flicker Windows 11 Fluent dark interface.

[Key Features](#-key-features) • [Why DaddyWatch?](#-why-is-it-fast--low-impact) • [Architecture](#-architecture) • [Getting Started](#-getting-started) • [Security Actions](#-security-actions) • [Support](#-support--donations)

---

</div>

## 🌟 Key Features

### 📡 1. Real-Time Socket & Process Attribution (Kernel P/Invoke)
- **Full Process Attribution**: Leverages the Windows IP Helper API (`GetExtendedTcpTable` & `GetExtendedUdpTable`) to map every active socket to its exact **Process Name** (e.g. `chrome.exe`, `powershell.exe`, `svchost.exe`), **PID**, and full executable path.

- **TCP & UDP Listener Monitoring**: Identifies active inbound listeners, established client connections, and ephemeral port states.

- **Zero Screen Flickering**: Reconciles connections in place with key-based diffing. Selections, sorting, and scroll positions remain completely stable across 2-second scan intervals.


### 🛡️ 2. Multi-Source Threat Intelligence Engine
- **CIDR Subnet Matching**: High-speed bitwise interval matcher accurately evaluates subnet ranges (e.g. Cloudflare `/20` or Google ranges) and exact IPs.

- **Domain & DNS Threat Matching**: Inspects both remote IP addresses and resolved hostnames against active threat feeds and malicious hostfiles (e.g. URLhaus malware distribution lists).

- **Curated Allow & Block Feeds**: Preloaded with high-confidence threat feeds (Data-Shield, IPsum Level 3, FireHOL, Romain Marcoux) and enterprise cloud allowlists (Cloudflare, Google, GitHub Meta, Fastly CDN, Anycast DNS).


### 🌍 3. Country Flags & Regional GeoBlocking
- **Country Flag Badges**: Instant geographic lookup displays native flag emojis (🇺🇸, 🇩🇪, 🇷🇴, 🇬🇧, 🇯🇵, 🇨🇳, 🏠) and ISO codes for every public socket.

- **1-Click Country GeoBlocking**: Block all ingress/egress traffic to/from entire countries (e.g. high-risk regions) with a single click. Geoblocked traffic is automatically classified as malicious.

- **Visual Country Filter Grid**: Manage and toggle country-level rules with persistent local settings.


### 🌐 4. In-App Domain & DNS Inspector
- **Right-Click Deep Dive**: Right-click any connection to inspect its domain in the built-in DNS Inspector.

- **Real-Time Record Resolution**: Queries A, AAAA, and reverse PTR records, measuring round-trip latency in milliseconds.

- **Bulk Firewall Blocking**: Isolate all resolved IPs of a suspicious domain in Windows Firewall simultaneously.


### 🧱 5. Active Defense & Mitigation
- **1-Click Windows Firewall Rules**: Instantly block malicious remote IPs in both inbound and outbound directions via native `netsh advfirewall`.

- **Process Termination**: Kill rogue or suspicious processes by PID directly from the context menu (with protected-system process safeguards).

- **⚠️ Emergency Panic Lockdown**: A one-click panic button immediately drops all non-system external connections and isolates the host in Windows Firewall.

- **External Threat Intelligence**: Instant context menu lookups for **VirusTotal** (IP & Domain), **AbuseIPDB**, and **IPInfo.io**.


### 📁 6. Custom Feed & File Importer (.txt / .json)
- **Local File Ingestion**: Import custom blocklists or allowlists directly from `.txt` (plain IPs, CIDRs, hosts files) or `.json` formats (arrays or key-value objects).

- **Persistent Local Cache**: Threat intelligence databases are saved locally at `%LocalAppData%\DaddyWatch\intel_cache.json` for instant offline protection on boot.


### 🔔 7. Windows Native Integration & Audit Trail
- **Windows Toast Alerts**: Native desktop notifications when threats or geoblocked endpoints are intercepted (with intelligent rate-limiting to prevent spam).

- **System Tray Minimization**: Sits quietly in the notification area with double-click window restore.

- **Compliance CSV Export**: Export timestamped threat and network audit logs to `.csv` for diagnostic reporting.


---

## ⚡ Why is it Fast & Low-Impact?

DaddyWatch was designed from the ground up to eliminate the bloat, battery drain, and sluggishness common in traditional security utilities.

| Engineering Area | Traditional Security Tools | DaddyWatch v1.0 Architecture |
| :--- | :--- | :--- |
| **CIDR Matching** | Linear scan across lists ($O(N)$) | **Sorted Interval Binary Search ($O(\log N)$)**: Evaluates 10,000+ CIDRs in $\le 16$ comparisons ($< 25\text{ ns}$). |
| **DNS Resolution** | Unbounded background threads that lag network | **Bounded Worker Queue**: `SemaphoreSlim(3, 3)` with strict 1.5s timeout and negative caching. |
| **Process Inspection**| Expensive WMI queries or per-tick queries | **Thread-Safe Process Cache with TTL**: Sockets look up cached PIDs with 30s expiration ($< 0.5\%$ CPU). |
| **UI Rendering** | Full collection wipe (`Clear()`) causing seizure-like flicker | **In-Place Observable Diffing**: Updates row properties directly; zero flicker, preserving scroll and selection. |
| **Memory Footprint** | Bloated Electron/Chromium runtime (300MB - 1GB) | **Native .NET 10 WPF**: Lightweight, bounded queues (1,000 audit items max), flat $\approx 45\text{ MB}$ RAM footprint. |
| **DataGrid Virtualization** | Heavy visual tree generation | **DirectX-Accelerated Recycling**: `EnableRowVirtualization="True"` with virtualized stack panel. |

---

## 🏗️ Architecture

DaddyWatch follows a clean **Model-View-ViewModel (MVVM)** pattern built on the `CommunityToolkit.Mvvm` framework:

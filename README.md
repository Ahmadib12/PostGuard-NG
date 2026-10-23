# PostGuard NG 🛡️🇳🇬
> Intelligent API Security Middleware & Spoof-Prevention Firewall for Nigeria's National Digital Alphanumeric Postcode Infrastructure (`docs.postcode.gov.ng`).

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Pitch Ready](https://img.shields.io/badge/3MTT-Pitch%20Ready-orange)]()

---

## 🚀 Overview
**PostGuard NG** is a high-performance security proxy and middleware solution built for Nigeria's National Digital Alphanumeric Postcode System. As fintechs, logistics networks, and emergency services plug directly into NIPOST's geospatial infrastructure, spatial datasets become prime targets for automated scrapers, volumetric attacks, and location-spoofing fraud.

PostGuard NG acts as an intelligent shield at the edge, intercepting, scrubbing, and validating requests **before** they hit NIPOST's backend endpoints.

---

## ⚙️ Core Architectural Features

1. **HMAC-SHA256 Payload Integrity Verification**
   * Eliminates Man-in-the-Middle (MitM) tampering and request replay attacks. Every partner request requires a cryptographically signed header.
2. **Dynamic Rate-Limiting & DDoS Shield**
   * Implements token-bucket rate limits (backed by memory/Redis stores) to block malicious web scrapers and volumetric API flooding.
3. **Geo-Behavioral Anomaly Engine (Anti-Spoofing)**
   * Cross-references the requester's device and network metadata (IP/telemetry radius) against the spatial boundaries of the requested 11-character NIPOST building code (e.g., matching regional codes like `FC 02...` for Abuja). 
   * Flags and blocks cross-state coordinate falsification attempts instantly.

---

## 🛠️ Tech Stack
* **Framework:** Python / FastAPI (Chosen for async performance and speed)
* **Validation & Security:** Pydantic, HMAC-SHA256 cryptographic hashing
* **Rate Limiting Engine:** Redis-ready sliding window architecture

---

## 📦 Getting Started Locally

### 1. Clone the Repository
```bash
git clone [https://github.com/your-username/postguard-ng.git](https://github.com/your-username/postguard-ng.git)
cd postguard-ng

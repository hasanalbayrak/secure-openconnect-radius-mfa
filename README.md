# Secure OpenConnect VPN with Radius MFA & BCrypt

An enterprise-grade, dockerized VPN solution utilizing **OpenConnect (ocserv)** and **FreeRADIUS**. This repository implements a custom Python-based authentication module designed for high-security environments, featuring SMS-based Multi-Factor Authentication (MFA), BCrypt password hashing, and anti-phishing reference codes.

## Features

* **OpenConnect Server:** Robust, Cisco AnyConnect-compatible VPN server running on Alpine Linux.
* **Centralized Authentication:** FreeRADIUS 3.x integration.
* **Secure MFA:** SMS-based One-Time Password (OTP) verification.
* **Anti-Phishing Protection:** Displays a unique Reference Code in the SMS and VPN prompt to verify transaction legitimacy.
* **BCrypt Hashing:** Passwords are stored securely using industry-standard hashing algorithms.
* **Secure Logging:** Personally Identifiable Information (PII) is masked in system logs.
* **Internal Routing:** Configured to allow secure access to internal Docker networks.

## Architecture

1.  **Client Connection:** The user connects via AnyConnect Client using their Username and Static Password.
2.  **Phase 1 (Authorization):** Radius verifies the static password against the BCrypt hash in `users.json`.
3.  **OTP Generation:** A Python module generates a 6-digit OTP and a Reference Code.
4.  **SMS Dispatch:** The OTP is sent via the configured SMS Provider API.
5.  **Challenge-Response:** The VPN session pauses and requests the OTP, displaying the Reference Code to the user.
6.  **Phase 2 (Authentication):** The user enters the OTP. The system validates it against the active session.
7.  **Access Granted:** Upon success, the user is granted access to the network.

## Prerequisites

* Docker Engine
* Docker Compose
* A valid SMS Provider API (Default implementation supports Verimor API)

## Installation

### 1. Clone the Repository
```bash
git clone [https://github.com/your-org/secure-vpn-radius.git](https://github.com/your-org/secure-vpn-radius.git)
cd secure-vpn-radius
```

### 2. Configure Environment Variables
Create a ```.env``` file from the example and populate it with your credentials.
```bash
cp .env.example .env
vi .env
```
Ensure you configure the ```RADIUS_SECRET``` and SMS API credentials accurately.
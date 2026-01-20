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
https://github.com/hasanalbayrak/secure-openconnect-radius-mfa.git
cd secure-vpn-radius
```

### 2. Configure Environment Variables
Create a ```.env``` file from the example and populate it with your credentials.
```bash
cp .env.example .env
```
Ensure you configure the ```RADIUS_SECRET``` and SMS API credentials accurately.

### 3. User Configuration
Copy the user database example.
```bash
cp radius/users.json.example radius/users.json
```
**Security Note:** Passwords must be hashed using BCrypt. Do not store plain-text passwords.

#### Generating a Password Hash

To generate a BCrypt hash without installing local dependencies, run the following command within the Docker environment:
```bash
docker compose run --rm radius python3 -c "import bcrypt; p = input('Enter Password: '); print(bcrypt.hashpw(p.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'))"
```
Copy the output hash (starting with ```$2b$...```) into your ```users.json``` file.

### 4. Deployment

Build and start the services.
```bash
docker compose up -d -build
```

## Network Configuration
* VPN Client Subnet: ```10.10.10.0/24```
* Internal Management Network: ```172.21.0.0/16```
* VPN Gateway IP: ```172.21.0.1```

VPN clients are routed to access services running on the ```172.21.0.0/16``` subnet securely.

## Logs & Troubleshooting
View logs for the Radius service to debug authentication issues. PII is masked by default.

## License
This project is licensed under the MIT License.
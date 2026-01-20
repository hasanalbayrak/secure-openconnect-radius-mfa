#!/bin/bash
set -e

# --- 1. Certificate Generation (Self-Signed) ---
if [ ! -f /etc/ocserv/server-key.pem ]; then
    echo ">> Generating self-signed certificates..."
    cd /etc/ocserv

    cat > ca.tmpl <<EOT
cn = "VPN CA"
organization = "${VPN_ORG_NAME}"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOT

    cat > server.tmpl <<EOT
cn = "${VPN_DOMAIN}"
organization = "${VPN_ORG_NAME}"
expiration_days = 3650
signing_key
encryption_key
tls_www_server
EOT

    certtool --generate-privkey --outfile ca-key.pem
    certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem
    certtool --generate-privkey --outfile server-key.pem
    certtool --generate-certificate --load-privkey server-key.pem \
    --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
    --template server.tmpl --outfile server-cert.pem
fi

# --- 2. Radius Client Configuration ---
echo ">> Configuring Radius Client..."
echo "$RADIUS_SERVER  $RADIUS_KEY" > /etc/radcli/servers

cat > /etc/radcli/radiusclient.conf <<EOT
auth_order radius
login_tries 4
login_timeout 60
radius_timeout 10
radius_deadtime 0
bindaddr *
authserver $RADIUS_SERVER:1812
acctserver $RADIUS_SERVER:1813
servers /etc/radcli/servers
dictionary /etc/radcli/dictionary
default_realm
radius_retries 3
EOT

if [ ! -f /etc/radcli/dictionary ]; then
    touch /etc/radcli/dictionary
fi

# --- 3. Ocserv Server Configuration ---
mkdir -p /run/ocserv

cat > /etc/ocserv/ocserv.conf <<EOT
auth = "radius[config=/etc/radcli/radiusclient.conf]"

server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem
ca-cert = /etc/ocserv/ca-cert.pem

tcp-port = 4443
udp-port = 4443
run-as-user = root
run-as-group = root
socket-file = /run/ocserv/ocserv.sock
isolate-workers = true
max-clients = 1024
max-same-clients = 2
server-stats-reset-time = 604800
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = true
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /run/ocserv/ocserv.pid
device = vpns
predictable-ips = true
default-domain = ${VPN_DOMAIN}
ipv4-network = 10.10.10.0
ipv4-netmask = 255.255.255.0

# DNS Configuration
dns = 8.8.8.8
dns = 1.1.1.1

# Internal Routing
# Allows VPN clients to access the Docker container network
route = 172.21.0.0/255.255.0.0
route = default

EOT

# --- 4. Network Address Translation (NAT) & Start ---
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE

echo ">> Starting Ocserv VPN..."
exec ocserv -c /etc/ocserv/ocserv.conf -f -d 1
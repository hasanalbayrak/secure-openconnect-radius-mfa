FROM debian:bookworm-slim

# Paketleri güncelle ve kur
# ocserv: VPN Sunucusu
# iptables: NAT ayarları için
# gnutls-bin: Sertifika işlemleri için
# gettext-base: envsubst vb. gerekirse diye (opsiyonel ama tutalım)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ocserv \
    iptables \
    gnutls-bin \
    gettext-base \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Çalışma ve Config dizinleri
RUN mkdir -p /etc/ocserv /etc/radcli /run/ocserv

# Entrypoint scriptini kopyala
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Portlar
EXPOSE 4443/tcp 4443/udp

ENTRYPOINT ["/entrypoint.sh"]
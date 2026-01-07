# Use a slim version of Debian to reduce image size (Ubuntu latest is too heavy)
FROM debian:bookworm-slim

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install PowerDNS and the MySQL backend
RUN apt-get update && apt-get install -y \
    pdns-server \
    pdns-backend-mysql \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration
COPY pdns.conf /etc/powerdns/pdns.conf

# Expose DNS ports (UDP and TCP)
EXPOSE 53/udp 53/tcp

# Run PowerDNS in the foreground so Docker can track it
CMD ["pdns_server", "--daemon=no", "--guardian=no", "--loglevel=9"]
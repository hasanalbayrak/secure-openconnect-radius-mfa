FROM freeradius/freeradius-server:latest

# Install Python3, pip, and required libraries
# python3-bcrypt is essential for password hashing
RUN apt-get update && apt-get install -y \
    python3 \
    python3-dev \
    python3-pip \
    python3-requests \
    python3-bcrypt \
    && rm -rf /var/lib/apt/lists/*

# Link the Python3 module to enabled modules
RUN ln -s /etc/raddb/mods-available/python3 /etc/raddb/mods-enabled/python3

# Enable detailed authentication logging
RUN sed -i 's|#\s*auth = yes|auth = yes|g' /etc/raddb/radiusd.conf
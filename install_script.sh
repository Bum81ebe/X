#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root."
  exit
fi

# Step 0: Clean up existing installations
echo "Uninstalling HAProxy, ddos-deflate, and UFW if already installed..."

# Uninstall HAProxy
if dpkg-query -W -f='${Status}' haproxy 2>/dev/null | grep -q "installed"; then
  echo "Removing HAProxy..."
  systemctl stop haproxy
  apt remove --purge -y haproxy
  rm -rf /etc/haproxy
fi

# Uninstall ddos-deflate
if [ -d "/usr/local/ddos" ]; then
  echo "Removing ddos-deflate..."
  /usr/local/ddos/uninstall.sh
fi

# Uninstall UFW and conflicting packages
if dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep -q "installed"; then
  echo "Removing UFW..."
  ufw disable
  apt remove --purge -y ufw
fi

echo "Removing conflicting packages..."
apt remove --purge -y iptables-persistent netfilter-persistent
apt autoremove -y

# Clear all iptables rules
echo "Clearing all iptables rules..."
iptables -F   # Flush all chains
iptables -X   # Delete all user-defined chains
iptables -Z   # Zero all packet and byte counters
iptables -t nat -F  # Flush NAT table
iptables -t mangle -F  # Flush Mangle table
iptables -t raw -F  # Flush Raw table
iptables -P INPUT ACCEPT   # Set default policy for INPUT chain
iptables -P FORWARD ACCEPT # Set default policy for FORWARD chain
iptables -P OUTPUT ACCEPT  # Set default policy for OUTPUT chain

# Resolve potential package dependency issues
echo "Resolving package dependency conflicts..."
apt-mark unhold ufw iptables-persistent netfilter-persistent

# Update package list
echo "Updating package list..."
apt update && apt upgrade -y

# Preconfigure iptables-persistent to accept rules automatically
echo "Preconfiguring iptables-persistent..."
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

# Reinstall iptables-persistent and netfilter-persistent
echo "Installing iptables-persistent and netfilter-persistent..."
apt install -y iptables-persistent netfilter-persistent || {
  echo "Failed to install iptables-persistent or netfilter-persistent. Exiting."
  exit 1
}

# Install UFW
echo "Installing UFW..."
apt install -y ufw || {
  echo "Failed to install UFW. Exiting."
  exit 1
}

# Install core tools
echo "Installing core tools..."
apt install -y dos2unix grepcidr net-tools tcpdump dsniff haproxy git || {
  echo "Failed to install required packages. Exiting."
  exit 1
}

# Install additional tools
echo "Installing additional tools..."
if ! command -v tcpkill &> /dev/null; then
  apt install -y dsniff
fi

if ! command -v grepcidr &> /dev/null; then
  wget http://www.pc-tools.net/files/unix/grepcidr-2.0.tar.gz -O /tmp/grepcidr-2.0.tar.gz
  cd /tmp
  tar -xvzf grepcidr-2.0.tar.gz
  cd grepcidr-2.0
  make
  make install
  cd ..
  rm -rf /tmp/grepcidr-2.0 /tmp/grepcidr-2.0.tar.gz
fi

# Clone and install ddos-deflate
echo "Cloning and installing ddos-deflate..."
git clone https://github.com/jgmdev/ddos-deflate /tmp/ddos-deflate
cd /tmp/ddos-deflate
./install.sh

# Prompt for server ports and main.exe instances
while true; do
  read -p "Enter the ports for Mu Online server (space-separated or comma-separated, e.g., 44405,55901,55919 or 44405 55901 55919): " SERVER_PORTS

  # Replace commas with spaces to normalize the input
  SERVER_PORTS=$(echo "$SERVER_PORTS" | tr ',' ' ')

  VALID_PORTS=""
  INVALID_PORTS=0

  # Validate each port
  for PORT in $SERVER_PORTS; do
    if [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; then
      VALID_PORTS="$VALID_PORTS $PORT"
    else
      echo "Invalid port detected: $PORT. Ports must be numeric and between 1 and 65535."
      INVALID_PORTS=1
    fi
  done

  # If all ports are valid, break the loop
  if [ "$INVALID_PORTS" -eq 0 ]; then
    SERVER_PORTS=$VALID_PORTS
    break
  else
    echo "Please enter the ports again."
  fi
done

read -p "Enter the maximum number of main.exe instances: " MAX_INSTANCES
read -p "Enter the IP address of the Mu Online server: " SERVER_IP

# Calculate NO_OF_CONNECTIONS
NO_OF_CONNECTIONS=$((MAX_INSTANCES * 5))

# Configure iptables rules
echo "Configuring iptables rules..."
iptables -F
iptables -X
iptables -Z
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow ports 22 and 21 without limits
iptables -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT

# Allow incoming connections for server ports with connection limits
for PORT in $SERVER_PORTS; do
  iptables -A INPUT -p tcp --dport $PORT -m connlimit --connlimit-above $NO_OF_CONNECTIONS -j REJECT --reject-with tcp-reset
  iptables -A INPUT -p tcp --dport $PORT -m state --state NEW,ESTABLISHED -j ACCEPT
done

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

echo "Iptables rules configured successfully!"

# Configure UFW rules
echo "Configuring UFW rules..."
ufw default deny incoming
ufw default allow outgoing

# Allow ports 22 and 21 without limits
ufw allow 22/tcp
ufw allow 21/tcp

# Allow specified server ports with connection limits
for PORT in $SERVER_PORTS; do
  ufw allow $PORT/tcp
  iptables -A INPUT -p tcp --dport $PORT -m connlimit --connlimit-above $NO_OF_CONNECTIONS -j REJECT --reject-with tcp-reset
done

# Enable UFW
echo "y" | ufw enable

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

echo "Firewall configuration complete!"


# Generate the complete ddos.conf file
PORT_CONNECTIONS=""
for PORT in $SERVER_PORTS; do
  PORT_CONNECTIONS="$PORT_CONNECTIONS $PORT:$NO_OF_CONNECTIONS:5"
done

cat <<EOL > /etc/ddos/ddos.conf
# Paths of the script and other files
PROGDIR="/usr/local/ddos"
SBINDIR="/usr/local/sbin"
PROG="\$PROGDIR/ddos.sh"
IGNORE_IP_LIST="ignore.ip.list"
IGNORE_HOST_LIST="ignore.host.list"
CRON="/etc/cron.d/ddos"
APF="/usr/sbin/apf"
CSF="/usr/sbin/csf"
IPF="/sbin/ipfw"
IPT="/sbin/iptables"
IPT6="/sbin/ip6tables"
TC="/sbin/tc"


# frequency in minutes (max: 59) for running the script as a cron job
# A minimum value of 1 is recommended for the script to be effective.
# Caution: Every time this setting is changed, run the script with --cron
#          option so that the new frequency takes effect.
# Warning: This option is deprecated and you should run the ddos-deflate
#          script in daemon mode which it is more effective.

FREQ=1

# frequency in seconds when running as a daemon

DAEMON_FREQ=5

# How many connections define a bad IP per user? Indicate that below.

NO_OF_CONNECTIONS=$NO_OF_CONNECTIONS

# Only count incoming connections to listening services, which will
# prevent the server from banning multiple outgoing connections to
# a single ip address. (slower than default in/out method)

ONLY_INCOMING=true

# If set to true the script will also use tcpdump to scan for ip
# addresses given in the CF-Connecting-IP header tag sent by cloudflare
# servers and ban using iptables string matching module.

ENABLE_CLOUDFLARE=false

# This option enables the usage of PORT_CONNECTIONS. Same as ONLY_INCOMING
# but you can also assing blocking rules per port using PORT_CONNECTIONS.
# (slower than ONLY_INCOMING method)

ENABLE_PORTS=true

# Maximum amount of connections per port before blocking. If a user
# is making all its connections to a single port the max connections
# specified for the port will take precedence over the
# NO_OF_CONNECTIONS value.
# You should specify a rule for all the service ports your server is
# running since those ports not defined on this list will be ignored
# when ENABLE_PORTS is enabled making those ports vulnerable to attacks.
# The form for each port element should be:
# "<from_port[-to_port]>:<max_conn>:<ban_period>"

PORT_CONNECTIONS="$PORT_CONNECTIONS"

# The firewall to use for blocking/unblocking, valid values are:
# auto, apf, csf, ipfw, and iptables

FIREWALL="iptables"

# An email is sent to the following address when an IP is banned.
# Blank would suppress sending of mails

EMAIL_TO="vandghuladze36@gmail.com"

# Number of seconds the banned ip should remain in blacklist.

BAN_PERIOD=600

# Connection states to block. See: man ss
# each state should be separated by a colon (:), for example:
# "established:syn-sent:syn-recv:fin-wait-1:fin-wait-2"
# by default it blocks all states except for listening and closed

CONN_STATES="connected"

# Connection states to block when using netstat. See: man netstat

CONN_STATES_NS="ESTABLISHED|SYN_SENT|SYN_RECV|FIN_WAIT1|FIN_WAIT2|TIME_WAIT|CLOSE_WAIT|LAST_ACK|CLOSING"

# Monitor bandwidth usage per ip and slows down data transfer rate/s if
# the BANDWIDTH_CONTROL_LIMIT is exceeded. (Requires iftop and tc)

BANDWIDTH_CONTROL=false

# The data transfer rate/s that triggers a rate drop to the speed
# defined in BANDWIDTH_DROP_RATE, can be expressed in mbit or kbit.

BANDWIDTH_CONTROL_LIMIT="1896kbit"

# When the maximum data transfer rate defined in BANDWIDTH_CONTROL_LIMIT
# is reached, the speed of the transfer will be reduced to this value
# for the amount of seconds specified in BANDWIDTH_DROP_PERIOD.

BANDWIDTH_DROP_RATE="512kbit"

# The amount of time in seconds to keep a client transfer at the speed
# defined on BANDWIDTH_DROP_RATE.

BANDWIDTH_DROP_PERIOD=600

# If true, takes into consideration only the data received from
# client and not the data sent by server to client.

BANDWIDTH_ONLY_INCOMING=true

EOL

echo "ddos.conf has been updated successfully!"

# Restart ddos-deflate
echo "Restarting ddos-deflate..."
/usr/local/ddos/ddos.sh --stop
/usr/local/ddos/ddos.sh --start

# Generate HAProxy configuration
echo "Generating HAProxy configuration..."
mkdir -p /etc/haproxy/errors
cat <<EOL > /etc/haproxy/haproxy.cfg
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 5000
    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 20s
    timeout client 50s
    timeout server 50s
    log-format "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq"
    option tcpka
    option tcplog
EOL

# Add frontend and backend configuration for each port
INDEX=1
for PORT in $SERVER_PORTS; do
  cat <<EOL >> /etc/haproxy/haproxy.cfg

frontend tcp_frontend_$PORT
    bind *:$PORT maxconn 5000
    stick-table type ip size 1m expire 10m store conn_rate(10s)
    tcp-request connection track-sc0 src table tcp_frontend_$PORT
    tcp-request session reject if { src_conn_rate(tcp_frontend_$PORT) gt $NO_OF_CONNECTIONS }
    tcp-request content reject if { sc0_conn_rate(tcp_frontend_$PORT) gt $NO_OF_CONNECTIONS }
    default_backend game_server$INDEX

backend game_server$INDEX
    balance roundrobin
    server game_server$INDEX $SERVER_IP:$PORT check port $PORT inter 2000 rise 2 fall 3
    option tcp-check
EOL
  INDEX=$((INDEX + 1))
done

cat <<EOL >> /etc/haproxy/haproxy.cfg

errorfile 400 /etc/haproxy/errors/400.http
errorfile 403 /etc/haproxy/errors/403.http
errorfile 408 /etc/haproxy/errors/408.http
errorfile 500 /etc/haproxy/errors/500.http
errorfile 502 /etc/haproxy/errors/502.http
errorfile 503 /etc/haproxy/errors/503.http
errorfile 504 /etc/haproxy/errors/504.http
EOL

# Restart HAProxy
echo "Restarting HAProxy..."
haproxy -c -f /etc/haproxy/haproxy.cfg || {
  echo "HAProxy configuration validation failed. Exiting."
  exit 1
}
systemctl restart haproxy

# Configure iptables
echo "Setting up iptables rules..."
mkdir -p /etc/iptables
for PORT in $SERVER_PORTS; do
  iptables -A INPUT -p tcp --dport $PORT -m connlimit --connlimit-above $NO_OF_CONNECTIONS -j REJECT --reject-with tcp-reset
done
iptables-save > /etc/iptables/rules.v4

echo "System updates, installation, and configuration complete!"

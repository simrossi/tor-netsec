#!/bin/bash

TORRC="/etc/tor/torrc"
TOR_DIR="/var/lib/tor/.tor"
NTP_SERVER="192.168.1.10"

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <exit_addr> <exit_name> <pkgs_directory>"
    exit 1
fi

exit_addr="$1"
exit_name="$2"
pkgs_directory="$3"

# Setting static ip
sudo nmcli c mod "Wired connection 1" ipv4.addresses $exit_addr/16 ipv4.method manual
sudo nmcli c mod "Wired connection 1" ipv4.gateway 192.168.1.1
sudo nmcli c mod "Wired connection 1" ipv4.dns 192.168.1.1
sudo nmcli c down "Wired connection 1" && sudo nmcli c up "Wired connection 1"

# Setting random delay
delay=$((RANDOM % 101))
tc qdisc add dev eth0 root netem delay ${delay}ms

# Setting ntp server
echo -e "[Time]\nNTP=$NTP_SERVER" > /etc/systemd/timesyncd.conf
systemctl restart systemd-timesyncd

# Installing packages
ls $pkgs_directory | xargs -I {} dpkg -i "$pkgs_directory/{}"

# Allowing tor binary to bind reserved ports
setcap CAP_NET_BIND_SERVICE=+eip /bin/tor

# Writing tor configuration
cat > $TORRC <<- EOM
# If enabled, adjusts default values of the configuration to simplify the setup of a testing Tor network
TestingTorNetwork 1

# This option is used when bootstrapping a new Tor network
# If enabled, don't perform self-reachability testing. Just upload server descriptor immediately
AssumeReachable 1

# Disable IPv6 address resolution, IPv6 ORPorts and IPv6 reachability checks
AddressDisableIPv6 1

# Activate control port for Nyx
ControlPort 9051
HashedControlPassword 16:50718F5106BBABC360E50C692440E9EED5413930420ADB31C50515D0CA # Hashed password 'tor'

# Listen for Tor connections on specified port
ORPort 9001 IPv4Only

# Disable client port from listening for connections from applications
SocksPort 0

# Set server nickname to use as reference instead of the fingerprint
Nickname $exit_name

# Set server address. Needed when running on private subnets
Address $exit_addr

# Set contact info for good practice
ContactInfo $exit_name

# Enable exit node
ExitRelay 1

# Directory authorities information
EOM

cat > $TOR_UNIT <<- EOM
[Unit]
Description=Anonymizing overlay network for TCP (multi-instance-master)

[Service]
Type=oneshot
User=debian-tor
RemainAfterExit=yes
ExecStart=/bin/true
ExecReload=/bin/true

[Install]
WantedBy=multi-user.target
EOM

systemctl restart tor

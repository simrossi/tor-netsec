#!/bin/bash

TORRC="/etc/tor/torrc"
TOR_DIR="/var/lib/tor/.tor"
NTP_SERVER="192.168.1.10"

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <da_addr> <da_name> <pkgs_directory>"
    exit 1
fi

da_addr="$1"
da_name="$2"
pkgs_directory="$3"

# Setting static ip
sudo nmcli c mod "Wired connection 1" ipv4.addresses $da_addr/16 ipv4.method manual
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

# Operate as an authorative directory server
AuthoritativeDirectory 1
V3AuthoritativeDirectory 1

# Advertise directory server on specified port
DirPort 80 IPv4Only

# Listen for Tor connections on specified port
ORPort 9001 IPv4Only

# Give the Guard flag to any node regardless of their uptime and bandwidth.
TestingDirAuthVoteGuard *

# Give the HSDir (Hidden Service Directory) flag to any node regardless of their uptime and bandwidth.
TestingDirAuthVoteHSDir *

# Disable client port from listening for connections from applications
SocksPort 0

# Set server nickname to use as reference instead of the fingerprint
Nickname $da_name

# Set server address. Needed when running on private subnets
Address $da_addr

# Set contact info for good practice
ContactInfo $da_name

# Specify data directory
DataDirectory $TOR_DIR

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

# Generate the keys and certificates
mkdir -p $TOR_DIR/keys
chown -R debian-tor:debian-tor $TOR_DIR
echo $(tr -dc A-Za-z0-9 </dev/urandom | head -c 12) | tor-gencert --create-identity-key -m 12 -a $da_addr:80 --passphrase-fd 0
mv "authority*" $TOR_DIR/keys

# Generate the fingerprint
sudo -u debian-tor tor --list-fingerprint --dirauthority "placeholder 127.0.0.1:80 0000000000000000000000000000000000000000"

# Generate the DirAuthority line
dirauthority="DirAuthority da1 orport=9001 no-v2 v3ident=$(grep 'fingerprint' $TOR_DIR/keys/authority_certificate | cut -d ' ' -f 2) $da_addr:80 $(cat $TOR_DIR/fingerprint | cut -d ' ' -f 2)"
echo $dirauthority >> $TORRC
echo $dirauthority
systemctl restart tor

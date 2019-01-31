#!/bin/sh

SERVER_IP="192.168.182.130"
ADMIN_IP="192.168.182.128"

iptables --flush

#Default Policies
iptables --policy INPUT DROP
iptables --policy OUTPUT ACCEPT
iptables --policy FORWARD DROP

#Allow loopback packets 
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

#Allow established and related connections
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#Allow HTTP and HTTPS traffic
iptables -A INPUT -i ens33 -p tcp -m tcp --dport 80 -d $SERVER_IP -j ACCEPT
iptables -A INPUT -i ens33 -p tcp -m tcp --dport 443 -d $SERVER_IP -j ACCEPT

#Allow SSH and FTP access for ADMIN_IP
iptables -A INPUT -i ens33 -p tcp -m tcp --dport 21 -s $ADMIN_IP -d $SERVER_IP -j ACCEPT
iptables -A INPUT -i ens33 -p tcp -m tcp --dport 22 -s $ADMIN_IP -d $SERVER_IP -j ACCEPT

#Log pinging abuse
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:

#Allow icmp echo requests
iptables -A INPUT -i ens33 -p icmp --icmp-type 8 -d $SERVER_IP -j ACCEPT

#Limiting the incoming icmp ping request:
iptables -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT

#Prevent SYN flood attack
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT

### DROP spoofing packets
iptables -A INPUT -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.168.0.0/24 -j DROP

iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

#Prevent Land Attacks
iptables -A INPUT -s $SERVER_IP -j DROP

# Droping all invalid packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# flooding of RST packets, smurf attack Rejection
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# These rules add scanners to the portscan list, and log the attempt.
iptables -A INPUT -p tcp -m recent --name portscan --set -m limit -j LOG --log-prefix "portscan:"
iptables -A INPUT -p tcp -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m recent --name portscan --set -m limit -j LOG --log-prefix "portscan:"
iptables -A FORWARD -p tcp -m recent --name portscan --set -j DROP



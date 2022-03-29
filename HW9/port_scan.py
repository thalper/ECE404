#!/usr/bin/env python

###  port_scan.py
###  Avi Kak  (kak@purdue.edu)
###  March 11, 2016

##  Usage example:
##
##          port_scan.py  moonshine.ecn.purdue.edu   1  1024
##  or
##
##          port_scan.py  128.46.144.123   1   1024

##  This script determines if a port is open simply by the act of trying
##  to create a socket for talking to the remote host through that port.

##  Assuming that a firewall is not blocking a port, a port is open if
##  and only if a server application is listening on it.  Otherwise the
##  port is closed.

##  Note that the speed of a port scan may depend critically on the timeout
##  parameter specified for the socket.  Ordinarily, a target machine
##  should immediately send back a RST packet for every closed port.  But,
##  as explained in Lecture 18, a firewall rule may prevent that from
##  happening.  Additionally, some older TCP implementations may not send
##  back anything for a closed port.  So if you do not set timeout for a
##  socket, the socket constructor will use some default value for the
##  timeout and that may cause the port scan to take what looks like an
##  eternity.

##  Also note that if you set the socket timeout to too small a value for a
##  congested network, all the ports may appear to be closed while that is
##  really not the case.  I usually set it to 0.1 seconds for instructional
##  purposes.

##  Note again that a port is considered to be closed if there is no
##  server application monitoring that port.  Most of the common servers
##  monitor ports that are below 1024.  So, if you are port scanning for
##  just fun (and not for profit), limiting your scans to ports below
##  1024 will provide you with quicker returns.

import sys, socket
import re
import os.path

if len(sys.argv) != 4:
    sys.exit('''Usage: 'port_scan.py  host  start_port  end_port' '''
             '''\nwhere \n host is the symbolic hostname or the IP address '''
             '''\nof the machine whose ports you want to scan, start_port is '''
             '''\nstart_port is the starting port number and end_port is the '''
             '''\nending port number''')

verbosity = 0;        # set it to 1 if you want to see the result for each   #(1)
                      # port separately as the scan is taking place

dst_host = sys.argv[1]                                                       #(2)
start_port = int(sys.argv[2])                                                #(3)
end_port = int(sys.argv[3])                                                  #(4)

open_ports = []                                                              #(5)
# Scan the ports in the specified range:
for testport in range(start_port, end_port+1):                               #(6)
    sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )               #(7)
    sock.settimeout(0.1)                                                     #(8)
    try:                                                                     #(9)
        sock.connect( (dst_host, testport) )                                 #(10)
        open_ports.append(testport)                                          #(11)
        if verbosity: print testport                                         #(12)
        sys.stdout.write("%s" % testport)                                    #(13)
        sys.stdout.flush()                                                   #(14)
    except:                                                                  #(15)
        if verbosity: print "Port closed: ", testport                        #(16)
        sys.stdout.write(".")                                                #(17)
        sys.stdout.flush()                                                   #(18)

# Now scan through the /etc/services file, if available, so that we can
# find out what services are provided by the open ports.  The goal here
# is to construct a dict whose keys are the port names and the values
# the corresponding lines from the file that are "cleaned up" for
# getting rid of unwanted white space:
service_ports = {}
if os.path.exists( "/etc/services" ):                                        #(19)
    IN = open("/etc/services")                                               #(20)
    for line in IN:                                                          #(21)
        line = line.strip()                                                  #(22)
        if line == '': continue                                              #(23)
        if (re.match( r'^\s*#' , line)): continue                            #(24)
        entries = re.split(r'\s+', line)                                     #(25)
        service_ports[ entries[1] ] =  ' '.join(re.split(r'\s+', line))      #(26)
    IN.close()                                                               #(27)
    
OUT = open("openports.txt", 'w')                                             #(28)
if not open_ports:                                                           #(29)
    print "\n\nNo open ports in the range specified\n"                       #(30)    
else:
    print "\n\nThe open ports:\n\n";                                         #(31)    
    for k in range(0, len(open_ports)):                                      #(32)
        if len(service_ports) > 0:                                           #(33)
            for portname in sorted(service_ports):                           #(34)
                pattern = r'^' + str(open_ports[k]) + r'/'                   #(35)
                if re.search(pattern, str(portname)):                        #(36)
                    print "%d:    %s" %(open_ports[k], service_ports[portname])
                                                                             #(37)
        else:
            print open_ports[k]                                              #(38)
        OUT.write("%s\n" % open_ports[k])                                    #(39)
OUT.close()                                                                  #(40)

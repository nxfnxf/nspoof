from scapy.all import *
import os

vIP = raw_input("Victim to reArp: ")
gIP = raw_input("Gateway to reArp: ")
lIP = raw_input("IP of your device: ")

def MACsnag(IP):
	ans, unans =  arping(IP)
	for s, r in ans:
		return r[Ether].src

def reArp():
        vMac = MACsnag(vIP)
        gMac = MACsnag(gIP)
	lMac = MACsnag(lIP)
        send(ARP(op = 2, pdst = gIP, psrc = vIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = vMac), count = 4)
        send(ARP(op = 2, pdst = vIP, psrc = gIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gMac), count = 4)
	send(ARP(op = 2, pdst = gIP, psrc = lIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = lMac), count = 4)
	send(ARP(op = 2, pdst = lIP, psrc = gIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gMac), count = 4)
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

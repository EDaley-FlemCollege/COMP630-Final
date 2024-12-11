#!/usr/bin/env python

from threading import Thread
import time,sys,subprocess,os
from scapy.all import Dot11, Dot11Deauth, Dot11Disas, RadioTap, Dot11Elt, sendp, sniff, conf, EAPOL, Dot11EltRSN

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST = os.path.join(SCRIPT_DIR, 'whitelist.txt')

bssids = ['5A:6D:67:AC:90:90']
mssid = "eridal"

if len(sys.argv) > 2:
	mssid = sys.argv[2]
if len(sys.argv) < 2:
	chan = input('Enter Channel: ')
else :
	chan=sys.argv[1]

subprocess.run("sudo airmon-ng check kill > /dev/null", shell=True, executable="/bin/bash")
subprocess.run("sudo airmon-ng start wlan0 > /dev/null", shell=True, executable="/bin/bash")
change_channel="sudo iwconfig wlan0 channel "+chan
subprocess.run(change_channel, shell=True, executable="/bin/bash")

COUNT_BEACON = 0
COUNT_DIS = 0
COUNT_DEAUTH = 0
COUNT_AUTH = 0
COUNT_SPOOF = 0
STATUS_EVIL = False

s=conf.L2socket(iface='wlan0')

def read_file(file):
	with open(file, 'r') as f:
		return [line.strip().casefold() for line in f.readlines()]

def Process_Frame(packet):
	if packet.type == 0:
		if (packet.subtype == 0 or packet.subtype ==2): #Association Request
			assoc_check(packet)
		if (packet.subtype == 4 or packet.subtype == 5): #Probe
			probe_check(packet)
		if packet.subtype == 8: #Beacon
			beacon_check(packet)
		if packet.subtype == 10: #Disassocation
			dis_check(packet)
		if packet.subtype == 11: #Authentication
			auth_check(packet)
		if packet.subtype == 12: #Deauthentication
			deauth_check(packet)

def counter():
	global COUNT_BEACON
	global COUNT_DIS
	global COUNT_DEAUTH
	global COUNT_AUTH
	global COUNT_SPOOF
	global STATUS_EVIL
	bflood_limit = 400
	oflood_limit = 50
	while True:
		time.sleep(3)
		if COUNT_BEACON >= bflood_limit:
			print(f"WARNING: BEACON FLOOD, {COUNT_BEACON} Frames Caputres")
		if COUNT_DIS >= oflood_limit:
			print(f"WARNING: DISASSOCIATION FLOOD, {COUNT_DIS} Frames Captured")
		if COUNT_DEAUTH >= oflood_limit:
			print(f"WARNING: DEAUTHENTICATION FLOOD, {COUNT_DEAUTH} Frames Captured")
		if COUNT_AUTH >= oflood_limit:
			print(f"WARNING: AUTHENTICATION FLOOD, {COUNT_AUTH} Frames Captured")
		if COUNT_SPOOF > 0:
			print(f"WARNING: {COUNT_SPOOF} Spoofed Frames Captured")
		if STATUS_EVIL is True:
			print("WARNING: EVIL TWIN")
		COUNT_BEACON = 0
		COUNT_DIS = 0
		COUNT_DEAUTH = 0
		COUNT_AUTH = 0
		COUNT_SPOOF = 0
		STATUS_EVIL = False

def assoc_check(packet):
	global COUNT_SPOOF
	ssid = str(packet[Dot11Elt].info)
	ssid = ssid.split("'")
	ssid = ssid[1]
	if len(ssid) == 0:
		COUNT_SPOOF += 1

def probe_check(packet):
	global COUNT_SPOOF
	ssid = str(packet[Dot11Elt].info)
	ssid = ssid.split("'")
	ssid = ssid[1]
	if len(ssid) == 0:
		COUNT_SPOOF += 1
	if (packet.addr1.casefold() in read_file(WHITELIST) and not packet.haslayer(Dot11EltRSN)):
                print(f"WARNING: Evil Twin")
                craft_deauth(packet,s)


def beacon_check(packet):
	global COUNT_BEACON
	global COUNT_SPOOF
	global STATUS_EVIL
	ssid = str(packet[Dot11Elt].info)
	ssid = ssid.split("'")
	ssid = ssid[1]
	bssid = packet.addr2
	if len(ssid) == 0:
		ssid = "None"
	if ssid == mssid and not packet.haslayer(Dot11EltRSN):
                STATUS_EVIL = True
                craft_deauth(packet,s)
                COUNT_BEACON += 1
                return None
	if bssid.casefold() not in read_file(WHITELIST):
		print(f"WARNING: Rogue AP, {ssid}, {bssid}")
		craft_deauth(packet,s)
		COUNT_BEACON += 1
		return None
	if not packet.haslayer(Dot11EltRSN):
		STATUS_EVIL = True
		craft_deauth(packet,s)
		COUNT_BEACON += 1
		return None
	if ssid == "None":
		COUNT_SPOOF += 1
	COUNT_BEACON += 1

def dis_check(packet):
	global COUNT_DIS
	if packet.addr2.casefold() in read_file(WHITELIST):
		COUNT_DIS += 1

def deauth_check(packet):
	global COUNT_DEAUTH
	if packet.addr2.casefold() in read_file(WHITELIST):
		COUNT_DEAUTH += 1

def auth_check(packet):
	global COUNT_AUTH
	if packet.addr1.casefold() in read_file(WHITELIST):
		COUNT_AUTH += 1

def craft_deauth(packet,s):
	deauth_frame_client=RadioTap()/Dot11(type=0,subtype=12,addr1=packet.addr2,addr2=packet.addr1,addr3=packet.addr1)/Dot11Deauth(reason=3)
	deauth_frame_AP = RadioTap()/Dot11(type=0,subtype=10,addr1=packet.addr1,addr2=packet.addr2,addr3=packet.addr1)/Dot11Disas(reason=3)
	for i in range(1,10):
		s.send(deauth_frame_client)
		s.send(deauth_frame_AP)

print("Starting IDS...")
print(f"IDS Whitelist: {read_file(WHITELIST)}")

counter_thread = Thread(target=counter)
counter_thread.daemon = True
counter_thread.start()

print("Started IDS")
print("-------------------------------------")
sniff(iface='wlan0',prn=Process_Frame,lfilter=lambda pkt: pkt.haslayer(Dot11), store=0)


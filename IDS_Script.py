#!/usr/bin/env python

from threading import Thread
import time,sys,subprocess
from scapy.all import Dot11, Dot11Deauth, Dot11Disas, RadioTap, sendp, sniff, conf, EAPOL

if len(sys.argv) < 2:
	chan = input('Enter Channel: ')
else :
	chan=sys.argv[1]
#bssid=sys.argv[2]

subprocess.run("sudo airmon-ng check kill > /dev/null", shell=True, executable="/bin/bash")
subprocess.run("sudo airmon-ng start wlan0 > /dev/null", shell=True, executable="/bin/bash")
change_channel="sudo iwconfig wlan0 channel "+chan
subprocess.run(change_channel, shell=True, executable="/bin/bash")

COUNT_BEACON = 0
COUNT_DIS = 0
COUNT_DEAUTH = 0
COUNT_AUTH = 0

s=conf.L2socket(iface='wlan0')

whitelist = {
	'eridal' : '5A:6D:67:AC:90:90',
	'donkey994' : '5A:6D:67:AE:0F:D8'
}

def Process_Frame(packet):
	if packet.type == 0:
		if (packet.subtype == 0 or packet.subtype ==2): #Association Request
			assoc_check(packet)
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
	bflood_limit = 400
	oflood_limit = 100
	while True:
		time.sleep(3)
		if COUNT_BEACON >= bflood_limit:
			print("BEACON FLOOD!!!")
		if COUNT_DIS >= oflood_limit:
			print("DISASSOCIATION FLOOD!!!")
		if COUNT_DEAUTH >= oflood_limit:
			print("DEAUTHENTICATION FLOOD!!!")
		if COUNT_AUTH >= oflood_limit:
			print("AUTHENTICATION FLOOD!!!")
		print("Cycle Reset")
		COUNT_BEACON = 0
		COUNT_DIS = 0
		COUNT_DEAUTH = 0
		COUNT_AUTH = 0

def assoc_check(packet):
	print("association frame")

def beacon_check(packet):
	global COUNT_BEACON
	COUNT_BEACON += 1

def dis_check(packet):
	global COUNT_DIS
	COUNT_DIS += 1

def deauth_check(packet):
	global COUNT_DEAUTH
	COUNT_DEAUTH += 1

def auth_check(packet):
	global COUNT_AUTH
	COUNT_AUTH += 1


'''
def Process_Frame(packet):

	if  ((packet.subtype == 11 and packet.seqnum == 1) or (packet.subtype == 0)) and packet.addr1.casefold() == bssid.casefold():

		Craft_Deauth(packet,s)

		print('Client Authentication detected :::: deauth frames injected toward client --> '+packet.addr2)

	elif packet.subtype == 0 and packet.addr1.casefold() == bssid.casefold() :

		Craft_Deauth(packet,s)

		print('Association Request detected ::::  deauth frames injected toward client --> '+packet.addr2)


def Craft_Deauth(packet,s):
	
	deauth_frame_client=RadioTap()/Dot11(type=0,subtype=12,addr1=packet.addr2,addr2=packet.addr1,addr3=packet.addr1)/Dot11Deauth(reason=3)
	deauth_frame_AP = RadioTap()/Dot11(type=0,subtype=10,addr1=packet.addr1,addr2=packet.addr2,addr3=packet.addr1)/Dot11Disas(reason=3)
	for i in range(1,100):
		s.send(deauth_frame_client)
		s.send(deauth_frame_AP)
'''

counter_thread = Thread(target=counter)
counter_thread.daemon = True
counter_thread.start()

print("Starting...")
sniff(iface='wlan0',prn=Process_Frame,lfilter=lambda pkt: pkt.haslayer(Dot11), store=0)


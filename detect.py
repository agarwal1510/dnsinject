import argparse
import logging
#import datetime
from os import uname
from subprocess import call
from sys import argv, exit
from time import ctime, sleep
from pprint import pprint
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

global interface
global file
global expr
global requests
global responses


def parseInput():
	global interface
	global expr
	global file

	parser = argparse.ArgumentParser()
	parser.add_argument('-i', metavar='interface', nargs='?')
	parser.add_argument('-r', metavar='tracefile', nargs='?')
	parser.add_argument('expression', nargs='*')
	args = parser.parse_args()
	
	if args.expression is not None:
		expr = ' '.join(args.expression)
	else:
		expr = None
	
	if args.r is not None:
		file = args.r
	else:
		file = None

	if args.i is not None:
		interface = args.i
	else:
		interface = None

	
def handler(pkt):
	global requests
	global responses

	if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
		return

	srcPort = pkt[UDP].sport
	if srcPort != 53:
		return #not DNS response
	
	destIP = pkt[IP].dst
	destPort = pkt[UDP].dport


	query = pkt[DNS].qd.qname
	dnsID = pkt[DNS].id
#	answer = pkt[DNS].qr
	answers = checkType(pkt[DNS].an, pkt[DNS].ancount)

	if len(answers) == 0:
		return
	
	tup = (dnsID, query)
	if tup in requests and str(answers) != str(responses[tup]):
		printAttackMsg(tup, answers,  datetime.fromtimestamp(pkt.time).strftime('%Y%m%d-%H:%M:%S'))
	else:
		requests.add(tup)
		responses[tup] = answers


def checkType(answers, size):
	ips = list()
	for i in range(0, size):
		if answers[i].type == 1:
			ips.append(answers[i].rdata)

	return ips 

def printAttackMsg(tup, ips, time):
	print("%s DNS Poisoning Attempt" % time)
	print("TXID %s Request %s" % tup)
	print("Answer 1: " + str(responses[tup]))
	print("Answer 2: " + str(ips))
	print("\n")

if __name__ == '__main__':
	
	requests = set()
	responses = dict()
	parseInput()
	
	if interface != None:
		if expr != None:
			dnsPacket = sniff(iface=interface, filter=expr, prn = handler)
		else:	
			dnsPacket = sniff(iface=interface, prn = handler)
	elif file != None:
		if expr != None:
			dnsPacket = sniff(offline=file, filter=expr, prn = handler)
		else:
			dnsPacket = sniff(offline=file, prn = handler)	
	else:
		if expr != None:
			dnsPacket = sniff(filter=expr, prn = handler)
		else:
			dnsPacket = sniff(prn = handler)



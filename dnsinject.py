import sys
from sys import argv
from scapy.all import *


def handler(packet):
	print (packet)

def parseArgs(argv):
	args = {}
	#print (argv)
	while argv:
		if argv[0][0] == '-':
			args[argv[0]] = argv[1]
		else:
			args['filter'] = argv[0]
		argv = argv[1:]
	return args


if __name__ == '__main__':
	args = {}
        while argv:
                if argv[0][0] == '-':
                        args[argv[0]] = argv[1]
                else:
                        args['filter'] = argv[0]
                argv = argv[1:]
	print (args)
	if '-i' in args:
		print (args['-i'])
		sniff( prn=handler, filter='udp port 53', store=0);


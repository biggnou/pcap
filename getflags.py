#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import argparse
import scapy.all as scapy

def dostuff( pcap ):
    pkts = scapy.rdpcap(pcap)
    flags = {
    	'F': 'FIN',
	'S': 'SYN',
	'R': 'RST',
    	'P': 'PSH',
    	'A': 'ACK',
    	'U': 'URG',
    	'E': 'ECE',
    	'C': 'CWR',
	}
    for p in pkts:
    	[flags[x] for x in p.sprintf('%TCP.flags%')]

pcap = ''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile')
    args = parser.parse_args()
    pcap = args.infile
    dostuff( pcap )

if __name__ == '__main__':
    main()

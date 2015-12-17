#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import scapy.all as s

def dostuff( pcap ):
    totpkt = totsyn = totsynack = totack = totfin = 0
    test = 0
    pkts = s.rdpcap(pcap)
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
        F = [flags[x] for x in p.sprintf('%TCP.flags%')]
        totpkt += 1
        if 'SYN' in F:
            totsyn += 1
            if 'ACK' in F:
                totsynack += 1
        if 'FIN' in F:
            totfin += 1
        if 'ACK' in F:
            totack += 1

        if 'SYN' and not 'ACK' in F and len(F) > 1:
            test += 1

    print('Total SYN:', totsyn, 'total SYN-ACK:', totsynack , 'and total ACK:', totack, 'total FIN:', totfin, 'for total pkts:', totpkt)
    print('TEST SYN no ACK but not SYN only:', test)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile')
    args = parser.parse_args()
    pcap = args.infile
    dostuff( pcap )

if __name__ == '__main__':
    main()

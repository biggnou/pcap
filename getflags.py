#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import scapy.all as s

def dostuff( pcap ):
    totpkt = totsyn = totsynack = totack = totfin = 0

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
        totpkt += 1
        if 'SYN' in [flags[x] for x in p.sprintf('%TCP.flags%')]:
            totsyn += 1
            if 'ACK' in [flags[x] for x in p.sprintf('%TCP.flags%')]:
                totsynack += 1
        if 'FIN' in [flags[x] for x in p.sprintf('%TCP.flags%')]:
            totfin += 1
        if 'ACK' in [flags[x] for x in p.sprintf('%TCP.flags%')]:
            totack += 1
            # if 'SYN' in [flags[x] for x in p.sprintf('%TCP.flags%')]:
            #     totack -= 1
        print [flags[x] for x in p.sprintf('%TCP.flags%')]

    print('Total SYN:', totsyn, 'total SYN-ACK:', totsynack , 'and total ACK:', totack, 'total FIN:', totfin, 'for total pkts:', totpkt)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile')
    args = parser.parse_args()
    pcap = args.infile
    dostuff( pcap )

if __name__ == '__main__':
    main()

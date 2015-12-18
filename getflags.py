#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import scapy.all as s

def dostuff( pcap ):
    totpkt = totsynonly = totsynack = totlegalack = totcongestioncontrol = 0
    totgracefullfin = totgracefullfinpsh = 0
    totrst = totrstack = 0
    totphsack = toturgack = totveryurg = 0
    totsyninvalid = totnoackillegal = 0
    totnull = totxmas = totsynfinscan = 0

    pkts = s.rdpcap(pcap)
    flags = {
    	'F': 'FIN', # RFC 793
	'S': 'SYN', # RFC 793
	'R': 'RST', # RFC 793
    	'P': 'PSH', # RFC 793
    	'A': 'ACK', # RFC 793
    	'U': 'URG', # RFC 793
    	'E': 'ECE', # RFC 3168
    	'C': 'CWR', # RFC 3168
	}

    for p in pkts:
        F = [flags[x] for x in p.sprintf('%TCP.flags%')]
        totpkt += 1
        # based on: http://www.symantec.com/connect/articles/abnormal-ip-packets

        if 'SYN' in F and len(F) == 1:
            totsynonly += 1

        if 'SYN' and 'ACK' in F and len(F) == 2:
            totsynack += 1

        if 'SYN' and not 'ACK' in F and len(F) > 1:
            totsyninvalid += 1

        if 'ACK' in F and len(F) == 1:
            totlegalack += 1

        if not 'SYN' and not 'ACK' in F and len(F) >= 1:
            totnoackillegal += 1

        if len(F) >= 6: # XMAS scan
            totxmas += 1

        if len(F) == 0: # MULL scan
            totnull += 1

        if 'SYN' and 'FIN' in F: # Any SYN-FIN scan
            totsynfinscan += 1

        if 'ECE' or 'CWR' in F: # TODO: needs breaking down to check if it really works
            totcongestioncontrol += 1

        if 'FIN' and 'ACK' in F and len(F) == 2:
            totgracefullfin += 1

        if 'FIN' and 'ACK' and 'PSH' in F and len(F) ==3:
            totgracefullfinpsh += 1

        if 'RST' in F and len(F) == 1:
            totrst += 1

        if 'RST' and 'ACK' in F and len(F) == 2:
            totrstack += 1

        if 'PSH' and 'ACK' in F and len(F) == 2:
            totphsack += 1

        if 'URG' and 'ACK' in F and len(F) == 2:
            toturgack += 1

        if 'PSH' and 'URG' and 'ACK' in F and len(F) == 3:
            totveryurg += 1

        # if not 'ACK' in F and len(F) > 1:
        #     print F

    print '-----'
    print 'Total number of packets:', totpkt
    print '-----'
    print 'SYN only:', totsynonly
    print 'SYN-ACK', totsynack
    print '--'
    print 'ACK only:', totlegalack
    print 'Congestion control (ECE or CWR) flag raised:', totcongestioncontrol
    print '-----'
    print 'Gracefull FIN:', totgracefullfin
    print 'Gracefull FIN and PSH:', totgracefullfinpsh
    print 'RST only:', totrst
    print 'RST ACK:', totrstack
    print '-----'
    print 'PSH ACK:', totphsack
    print 'URG ACK:', toturgack
    print 'Very urgent (PSH, URG, ACK):', totveryurg
    print '-----'
    print 'SYN and other flag but no ACK (invalid pkt):', totsyninvalid
    print 'No SYN no ACK (invalid pkt):', totnoackillegal
    print 'XMAS scan:', totxmas
    print 'NULL scan:', totnull
    print 'SYN-FIN scan:', totsynfinscan


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile')
    args = parser.parse_args()
    pcap = args.infile
    dostuff( pcap )

if __name__ == '__main__':
    main()

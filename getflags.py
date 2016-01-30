#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import scapy.all as s

def dostuff( pcap ):
    totpkt = totsynonly = totsynack = totlegalack = totcongestioncontrol = 0
    totgracefullfin = totgracefullfinpsh = 0
    totrst = totrstack = 0
    totece = totcwr = totsynece = 0
    totphsack = toturgack = totveryurg = 0
    totsyninvalid = totnoackillegal = totinvalidsynack = 0
    totnull = totxmas = totsynfinscan = 0

    pkts = s.rdpcap(pcap)

    flags = {'F':'FIN','S':'SYN','R':'RST','P':'PSH','A':'ACK','U':'URG','E':'ECE','C':'CWR'}

    for p in pkts:
        # print p.sprintf("%IP.len%") ## pkt size (TODO: try and detect jumb sized frames)
        F = [flags[x] for x in p.sprintf('%TCP.flags%')]
        totpkt += 1
        # based on: http://www.symantec.com/connect/articles/abnormal-ip-packets

        if 'SYN' in F and len(F) == 1:
            totsynonly += 1

        if all((f in F for f in ['SYN','ECE','CWR'])) and len(F) == 3:
            totsynece += 1

        if all((f in F for f in ['SYN','ACK'])) and len(F) == 2:
            totsynack += 1

        if all((f in F for f in ['SYN','ACK'])) and len(F) > 2:
            if not 'ECE' and not 'CWR' in F:
                totinvalidsynack += 1

        if 'SYN' in F and len(F) > 1:
            if 'ACK' not in F:
                if not any((f in F for f in ['ECE','CWR'])):
                    totsyninvalid += 1

        if 'ACK' in F and len(F) == 1:
            totlegalack += 1

        if 'ACK' not in F:
            if not any((f in F for f in ['SYN','RST'])):
                totnoackillegal += 1

        if len(F) >= 6:
            totxmas += 1

        if len(F) == 0:
            totnull += 1

        if all((f in F for f in ['SYN', 'FIN'])):
            totsynfinscan += 1

        if any((f in F for f in ['ECE','CWR'])):
            totcongestioncontrol += 1

        if 'ECE' in F:
            totece += 1

        if 'CWR' in F:
            totcwr += 1

        if all((f in F for f in ['FIN','ACK'])) and not 'PSH' in F:
            totgracefullfin += 1

        if all((f in F for f in ['FIN','ACK','PSH'])):
            totgracefullfinpsh += 1

        if 'RST' in F and len(F) == 1:
            totrst += 1

        if all((f in F for f in ['RST','ACK'])) and len(F) == 2:
            totrstack += 1

        if all((f in F for f in ['PSH','ACK'])) and len(F) == 2:
            totphsack += 1

        if all((f in F for f in ['URG','ACK'])) and len(F) == 2:
            toturgack += 1

        if all((f in F for f in ['PSH','URG','ACK'])) and len(F) == 3:
            totveryurg += 1

    print '-----'
    print 'Total number of packets:', totpkt
    print '-----'
    print 'SYN only:', totsynonly
    print 'SYN with ECE and CWR:', totsynece
    print 'SYN-ACK', totsynack
    print '--'
    print 'ACK only:', totlegalack
    print 'Congestion control (ECE or CWR) flag raised:', totcongestioncontrol
    print 'ECE:', totece, 'CWR:', totcwr, 'Tot congestion:', totece + totcwr
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
    print 'Invalid SYN-ACK (more flags but no congestion control):', totinvalidsynack
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

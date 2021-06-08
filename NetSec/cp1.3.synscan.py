from scapy.all import *

import sys
TIMEOUT=10
MIN_PORT=1
MAX_PORT=1025
# Sources:
# https://python.plainenglish.io/network-scanning-with-scapy-in-python-708ed176e63
# https://scapy.net/conf/scapy_pacsec05.pdf
def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    results = []
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])
    try:
        syn = IP(dst=ip_addr)/TCP(dport=[i for i in range(MIN_PORT,MAX_PORT)],flags="S")
    except:
        debug("Error: Check IP: {}".format(ip_addr))
        exit(-1)
    good,bad= sr(syn,timeout=TIMEOUT,verbose=False)
    for _,pkt in good:
        if pkt[TCP].flags.SA: 
            results.append(tuple((pkt[IP].src, pkt[TCP].sport)))
            rst = IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport, flags="R")
            send(rst, iface=conf.iface,verbose=False)
    for e in results:
        print('{},{}'.format(e[0],e[1]))

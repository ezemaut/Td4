import socket
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sr1, send, ICMP, send, sendp, Ether,sr, sniff,get_if_addr,conf, srp, ARP, RandShort

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('127.0.0.1',53))
print("Hay servidor")


def response(msg):
    
    packet = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(msg))

    packet[DNS].id = DNS(msg)[DNS].id
    print(packet.summary())
    print(bytes(packet))
    return bytes(packet)

while True:
    message, addr = s.recvfrom(512)
    dns_response = bytes(IP(dst='1.1.1.1') / UDP(dport=53) / DNS(id=DNS(message)[DNS].id, qr=1, ancount=1, an=DNSRR(rrname="example.com", type="A", rdata="192.168.0.1")))
    s.sendto(dns_response, addr)
    # s.sendto(response((message)), addr)
    break
    
    
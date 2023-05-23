import argparse
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP, get_if_addr, conf
from typing import List

parser = argparse.ArgumentParser(description='Poner nombre.')
parser.add_argument('-s', metavar='N', type=str,
                    help='Server DNS')
parser.add_argument('-d', metavar='N', action='append',
                    help='Dir web y dir ip')

args = parser.parse_args()

server:str = vars(args)["s"]
if  not server: #Si no hay servidor, tira error
        raise argparse.ArgumentTypeError("error: the following arguments are required: -s/--server")

print(vars(args)["s"],vars(args)["d"])

IFACE = "lo0"   # Or your default interface
DNS_SERVER_IP = get_if_addr(conf.iface)  # Your local IP

BPF_FILTER = f"udp port 53 and ip dst {DNS_SERVER_IP}"


def dns_responder(local_ip: str):

    def forward_dns(orig_pkt: IP):
        print(f"Forwarding: {orig_pkt[DNSQR].qname}")
        response = sr1(
            IP(dst=server)/
                UDP(sport=orig_pkt[UDP].sport)/
                DNS(rd=1, id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname)),
            verbose=0,
        )
        resp_pkt = IP(dst=orig_pkt[IP].src, src=DNS_SERVER_IP)/UDP(dport=orig_pkt[UDP].sport)/DNS()
        resp_pkt[DNS] = response[DNS]
        send(resp_pkt, verbose=0)
        return f"Responding to {orig_pkt[IP].src}"

    def get_response(pkt: IP):
        if (
            DNS in pkt and
            pkt[DNS].opcode == 0 and
            pkt[DNS].ancount == 0
        ):
            #ACA LOS PREDIterminaados
            if "trailers.apple.com" in str(pkt["DNS Question Record"].qname):
                spf_resp = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata=local_ip)/DNSRR(rrname="trailers.apple.com",rdata=local_ip))
                send(spf_resp, verbose=0, iface=IFACE)
                return f"Spoofed DNS Response Sent: {pkt[IP].src}"

            else:
                # make DNS query, capturing the answer and send the answer
                return forward_dns(pkt)

    return get_response

sniff(filter=BPF_FILTER, prn=dns_responder(DNS_SERVER_IP), iface=IFACE)
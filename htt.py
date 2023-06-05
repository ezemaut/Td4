
#curl http://www.google.com --resolve www.google.com:80:127.0.0.1

import argparse
import socket
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, Raw, ls, Ether
from scapy.layers import http
from scapy.layers.http import *

parser = argparse.ArgumentParser(description='Redireccion http y carga directa de archivos html a sitos.')
parser.add_argument('-c', metavar='--Archivo', type=str,
                    help='Nombre del archivo html')
parser.add_argument('-d', metavar='--Sitios Recividores', action='append', default=[],
                    help='Direcciones web que recibiran el archivo html')
parser.add_argument('-r', metavar='--Redirecciones', action='append', default=[],
                    help='Dirreciones web separadas por ":". La primera sera direccionada a la segunda')

args = parser.parse_args()

archivo:str = vars(args)["c"]
direcciones_archivo:list = vars(args)['d']

if len(direcciones_archivo)>0 and not archivo:
    raise argparse.ArgumentTypeError("indicar archivo -c")


redirecciones = vars(args)["r"]

dic_Pedido_Respueta = {}

for x in redirecciones:
    Pedido, Res = x.split(':')
    dic_Pedido_Respueta[Pedido] = Res



def packet_is_good(scapy_pkt:HTTP) -> bool:
    raw = Raw(scapy_pkt)
    payload = (raw[Raw].load).decode()
    if "GET" in payload:
        global host
        host = payload.split("Host: ")[1]
        host = host.split('\r\n')[0]
        print(f'Request GET recibido (Host: {host})')
        return True
    
def necesita_archivo() -> bool:
    rv = False
    if host in direcciones_archivo:
        rv = True
        print("necesita archivo")
    return rv

def necesita_redireccionar() -> bool:
    rv = False
    if host in dic_Pedido_Respueta.keys():
            rv = True
            print("necesita redi")
    return rv

def build_a_packet():
    destino = dic_Pedido_Respueta[host]
    http_response = (
        "HTTP/1.1 301 Moved Permanently\r\n"
        f"Location: https://{destino}\r\n"
        "\r\n")
    res = bytes_encode(http_response)
    res_pkt = res
    return res_pkt

socket_local = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_local.bind(('0.0.0.0',80))
print("Hay servidor")

socket_local.listen()
conn, addr = socket_local.accept()

print(f"Connected by {addr}")
while True:
    message = conn.recv(1024)
    # mirar data
    # si data esta en d -> mandar html
    # si data esta en r -> rediriccionar
    # no esta ninguno -> mandar a donde pide

    scapy_pkt = HTTP(message)

    if packet_is_good(scapy_pkt):
        
        if necesita_archivo():
            # mandar archivo
            pass

        elif necesita_redireccionar():
            res = build_a_packet()  
        # else: mandar()
   
   
   
    if not res:
        print('not message')
        break
    print(2)
    conn.sendall(res)

import argparse
import socket
from scapy.all import DNS, DNSQR, DNSRR

parser = argparse.ArgumentParser(description='DNS server location and direcctions to spoof')
parser.add_argument('-s', metavar='--Servidor', type=str, 
                    help='Server DNS')
parser.add_argument('-d', metavar='--Direcciones', action='append', default=[],
                    help='Direccion web y direccion ip con un ":" en el medio')

args = parser.parse_args()

fwd_server:str = vars(args)["s"]
if not fwd_server: #Si no hay servidor, tira error
        raise argparse.ArgumentTypeError("error: the following arguments are required: -s/--server")


###################################################################################################
#Extra para validar entradas ip de consola, (para ver si son direcciones validas)
def val(pos):
    #devuevle false si no es dir IP valida
    nums = []
    for ip in pos:
        nums = ip.split('.')
        if len(nums) == 4:
            for number in nums:
                if number.isnumeric():
                    if int(number) < 0 or int(number) > 255:
                     return False
                else: return False
        else: return False
    return True
def validacion(inp:list): 
    #Splitter de address y IP
    ips = []
    for input in inp:
        ips.append(input.split(':')[1])
    return val(ips)

ser = []
ser.append(fwd_server)
if not val(ser): #Si hay error en -s
     raise argparse.ArgumentTypeError("Direccion no valida en -s")

lista_predeterminda = vars(args)["d"]

if len(lista_predeterminda) > 0 and not validacion(lista_predeterminda):
    raise argparse.ArgumentTypeError("Direccion no valida en -d")
###################################################################################################


socket_local = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
socket_local.bind(('0.0.0.0',53))
print("Hay servidor")

dic_Names_IP = {}

for x in lista_predeterminda:
    name, ip = x.split(':')
    dic_Names_IP[name] = ip

name_list = list(dic_Names_IP) 

# lista_predeterminada contiene las direcciones -d sin el 'www.', ej: ['google.com:1.1.1.1']. Lista de strings

# dic_Names_IP Usa es un diccionario para -d. Usa como llave las direcciones sin el 'www.'
# y tiene como respuesta las direcciones IP. ej: {'google.com' : '1.1.1.1'}

# name_list es una lista de las direcciones -d sin el 'www.'. ej:['google.com']

def packet_is_good(scapy_pkt:DNS, IP:tuple) -> bool:
    # Chequeamos que no hubo falla en el mandando con opcode == 0
    # Chequeamos que no haya respuetas en el paquete con ancount == 0
    # Si es una query DNS correcta devuelve True y el mensaje de QUERY RECIBIDA
    # El criterio de correcto se basa en la guia de tp parte 9 de scapy

    condOpcode:bool = scapy_pkt[DNS].opcode == 0 
    condAncount:bool = scapy_pkt[DNS].ancount == 0

    dns_es_correcto:bool = condOpcode and condAncount

    if dns_es_correcto == True:
        qr = scapy_pkt.getlayer(DNSQR)
        type = qr.get_field('qtype').i2repr(qr, qr.qtype)
        adr = (scapy_pkt["DNS Question Record"].qname).decode()
        print( f"[*]Query recibida: {type} {adr[:-1]} (de {IP[0]}:{IP[1]})")
    else: 
        print(scapy_pkt["DNS Question Record"].qtype)

    return dns_es_correcto  

def predeterminado(scapy_pkt:DNS) -> bool:
    # Devuelve True si el pkt pide una direccion que esta en la lista para spoofear
    # y si el request es de tipo A
    res:bool = False
    in_list:bool  = False
    condType:bool = scapy_pkt["DNS Question Record"].qtype == 1 #tipo A

    for name in name_list:
        if name in str(scapy_pkt["DNS Question Record"].qname):
            in_list  = True
    
    res = condType and in_list
    return res

def spoof(scapy_pkt:DNS, addr):
        #Crea la respuesta DNS spoofeada, la devuelve al socket,
        # y printea el mensaje Respondiendo (predeterminado)

        qname = (scapy_pkt["DNS Question Record"].qname).decode()
        qname = qname[:-1] #Saca el ultimo caracter (.) para hacerlo compatible con TP
        ip_spoof = dic_Names_IP[qname]

        spf_resp = DNS(qr=1, id=scapy_pkt[DNS].id, ancount=1, 
                       an=DNSRR(rrname=scapy_pkt[DNSQR].qname, rdata= ip_spoof, ttl = 80)) 
        
        spf_resp["DNS Question Record"].qname = qname

        socket_local.sendto(bytes(spf_resp), addr)
        print( f'[*]Respondiendo {ip_spoof} (predeterminado)')
        return 

def forward_dns(pkt, addr):
    #Pide la request DNS al servidor deseado y la devuelve al socket
    # y printea el mensaje Respondiendo (vía x.x.x.x)
    socket_forward = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    socket_forward.sendto(bytes(pkt),(fwd_server,53))
       
    socket_forward.settimeout(3)
    try:
        response, r_addr = socket_forward.recvfrom(512)
        socket_local.sendto(response, addr)
    except socket.timeout:
        print("Timed out")
        socket_forward.close()
        return
        
    socket_forward.close()
    
    scapy_rsp = DNS(response)
    ancount = scapy_rsp[DNS].ancount
    Rrecord = scapy_rsp.getlayer(DNSRR)
    try:
        return_addres = Rrecord[ancount-1].rdata
        print(f'[*]Respondiendo {return_addres} (vía {fwd_server})')
    except:
        print(f'[*]Respondiendo sin Resource Record (vía {fwd_server})')
    return 
    
while True:
    try:
        message, addr = socket_local.recvfrom(512)#512 es el maximo para paquetes DNS UDP
        scpy_pkt = DNS(message)
        if packet_is_good(scpy_pkt, addr):

            if predeterminado(scpy_pkt):
                spoof(scpy_pkt, addr)

            else:forward_dns(message, addr)
    except:
        pass
        

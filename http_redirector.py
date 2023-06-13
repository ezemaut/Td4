#Mauter - Garcia Vence - Bedacarratz
import argparse
import socket
from scapy.all import Raw
from scapy.layers.http import *

parser = argparse.ArgumentParser(description='Redireccion http y carga directa de archivos html a sitos.')
parser.add_argument('-c', metavar='--Archivo', type=str,
                    help='Nombre del archivo html')
parser.add_argument('-d', metavar='--Sitios recibidores', action='append', default=[],
                    help='Direcciones web que recibiran el archivo html')
parser.add_argument('-r', metavar='--Redirecciones', action='append', default=[],
                    help='Dirreciones web separadas por ":". La primera sera direccionada a la segunda')

args = parser.parse_args()

archivo:str = vars(args)["c"]
direcciones_archivo:set = set(vars(args)['d'])
redirecciones:list = vars(args)["r"]

dic_Pedido_Respueta:dict = {}
try:
    for x in redirecciones:
        # Solo funciona si -r input es igual al de la consigna
        # ej: www.uba.ar:https://www.utdt.edu
        #Crea el diccionario para redirecciones
        Pedido, Res1, Res2 = x.split(':')
        dic_Pedido_Respueta[Pedido] = Res1 + ":" + Res2 
except:
    print(f"Error al ingresar -d, se guardaron las siguientes redirecciones: {dic_Pedido_Respueta}")


# archivo: es un string el cual es igual al nombre del archivo y su extension incluido en -c
# direcciones_archivo: es una set el cual contiene todas las direcciones que van a recibir el archivo -c
# dic_Pedido_Respueta: es un diccionario en el cual las llaves son las direcciones que al ser recibidas seran 
# redirigidas a el valor que tienen asociado

def packet_is_good(scapy_pkt:HTTP) -> bool:
    #Se fija que el paquete sea un GET,
    #consigue el Host del paquete
    #y printea el HOST
    raw = Raw(scapy_pkt)
    try:
        payload:str = (raw[Raw].load).decode()
    except:
        return False
    if "GET" in payload:
        try:
            global host
            host = payload.split("Host:")[1]
            host = host.split('\r\n')[0]
            host = host.strip()
            print(f'Request GET recibido (Host: {host})')
            return True
        except:
            print("Paquete no tiene Host")
            return False
        
def necesita_archivo() -> bool:
    #Se fija si la direccion recibida esta en direcciones_archivo
    rv:bool = False
    if host in direcciones_archivo:
        rv = True
    return rv

def build_a_packet_200():
    #Crea el paquete 200 con el archivo
    #y Printea que mando lo mando
    with open(archivo, 'r') as file:
        html_content:str = file.read()

    response:str = "HTTP/1.1 200 OK\r\n"
    response += "Content-Type: text/html\r\n"
    response += "\r\n"
    response += html_content
    print(f'[*] Respondiendo contenido del archivo {archivo}')
    return bytes_encode(response)

def build_a_packet_301():
    #Crea el paquete 301 con el destino que le corresponde
    #y printea que lo mando al destino
    if host in dic_Pedido_Respueta.keys():
        destino:str = dic_Pedido_Respueta[host]
    else: destino = 'https://' + host
    
    http_response = "HTTP/1.1 301 Moved Permanently\r\n"
    http_response += f"Location: {destino}\r\n"
    http_response += "\r\n"
    print(f'Respondiendo redirección hacia {destino}')
    return bytes_encode(http_response)

socket_local = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_local.bind(('0.0.0.0',80))
print("Hay servidor")

socket_local.listen()

while True:
    conn, addr = socket_local.accept()
    message = conn.recv(1024)
    scapy_pkt = HTTP(message)
    
    if packet_is_good(scapy_pkt):
        
        if necesita_archivo():
            res =build_a_packet_200()

        else: res =build_a_packet_301()    
    try:    
        if not res:
            break
    except:
        break

    conn.sendall(res)



#Mauter - Garcia Vence - Bedacarratz    

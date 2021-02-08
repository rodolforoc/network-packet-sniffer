import logging
from datetime import datetime
import subprocess
import sys

# Removendo mensagens de warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# Metodo recomendado para importar o scapy
try:
    from scapy.all import *

except ImportError:
    print("Scapy não está instalado no seu sistema.")
    sys.exit()

net_iface = input("* Digite a interface que voce deseja executar o sniffer (ex. 'enp0s8'): ")

try:
    subprocess.call(["ifconfig", net_iface, "promisc"], stdout = None, stderr = None, shell = False)

except:
    print("\n Falha na configuração da interface como PROMISC.\n")

else:
    print("\nInterface %s foi configurada com o modo PROMISC.\n" % net_iface)


# Quantidade de pacotes
pkt_to_sniff = input("* Digite a quantidade de pacotes que deseja executar (0 é infinito): ")

# Considerando 0 = infinito
if int(pkt_to_sniff) != 0:
    print("\nO programa irá capturar %d pacotes.\n" % int(pkt_to_sniff))
    
elif int(pkt_to_sniff) == 0:
    print("\nO programa irá capturar os pacotes até que o tempo expire.\n")

# Intervalo 
time_to_sniff = input("* Enter the number of seconds to run the capture: ")

if int(time_to_sniff) != 0:
    print("\nO programa irá capturar pacotes por %d segundos.\n" % int(time_to_sniff))
    
    
# Adicionando filtro de protocolo para ser aplicado no processo de sniff
# Exemplo: ARP, BOOTP, ICMP
proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")

# Caso usuario digite 0 (significa todos protocolos)
if (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    print("\nThe program will capture only %s packets.\n" % proto_sniff.upper())
    
elif (proto_sniff) == "0":
    print("\nThe program will capture all protocols.\n")


# Arquivo de Log
file_name = input("* Digite uma nome para o arquivo de log: ")

sniffer_log = open(file_name, "a")


# Funcao chamada toda vez que for capturado um pacote
# Extrair a informacao do pacote e escrever no arquivo de log
def packet_log(packet):
    
    now = datetime.now()
    
    # Escrevendo a informação no arquivo de log
    if proto_sniff == "0":
        print("Time: " + str(now) + " Protocol: ALL" + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)
        
    elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
        print("Time: " + str(now) + " Protocol: " + proto_sniff.upper() + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)

print("\n* Começando a captura...")

# Rodando o processo de sniff (com ou sem filtro)
if proto_sniff == "0":
    sniff(iface = net_iface, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)

elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    sniff(iface = net_iface, filter = proto_sniff, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)
    
else:
    print("\nNão foi possível identificar o protocolo.\n")
    sys.exit()

print("\n* Cheque o arquivo %s para ver os pacotes capturados.\n" % file_name)

sniffer_log.close()
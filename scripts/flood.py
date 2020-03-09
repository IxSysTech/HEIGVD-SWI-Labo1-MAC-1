#!/usr/bin/env python
'''
SWI - Labo1
Auteurs : Nemanja Pantic et David Simeonovic
But : Permet de générer plusieurs wifi à partir d'un fichier ou d'un générateur aléatoire
Source : https://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits
'''

from scapy.all import *
import random
import string
import argparse

# Cette méthode permet de générer un nom aléatoire
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

wifi = []

# Demande les saisies utilisateurs pour l'interface
iface = input("Give your interface name : ")

# On demande si l'utilisateur veut utiliser un fichier .txt , si il laisse blanc
# on utilisera le générateur aléatoire
file = input("Give file name, let blank if you want random SSID : ")

if file == "":
    for i in range(10):
        wifi.append(id_generator())
else:
    with open(file) as fp:
        for line in fp:
            wifi.append(line)
            print(line)

print(wifi)
frames = []

# Pour tous les SSID fournis, nous générons un paquet qui sera envoyé
for ssid in wifi:
    randomMac = RandMAC()

    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
    addr2=randomMac, addr3=randomMac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))

    frame = RadioTap()/dot11/beacon/essid
    frames.append(frame)

sendp(frames, iface=iface, inter=0.001, loop=1)

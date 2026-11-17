#!/usr/bin/env python3
"""step1.py : mesure le TTL de la reponse et le RTT de chaque hote.

Methode 1 : ping ICMP.
Methode 2 (si le ping ne repond pas) : connexion TCP sur les ports 443 puis 80.
Le TTL est lu dans l'en-tete IP de la reponse (echo reply ou SYN-ACK).

Usage (en administrateur) :
    python step1.py

Sortie : tableau a l'ecran et dans step1.txt
"""
import select
import socket
import struct
import time

from traceroute import build_echo

HOTES = [
    "www.usthb.dz",
    "www.univ-bejaia.dz",
    "www.ethz.ch",
    "www.kth.se",
    "www.u-tokyo.ac.jp",
    "www.anu.edu.au",
    "www.usp.br",
]

# Windows ne donne pas a Python le TTL des SYN-ACK (TCP) : ces valeurs ont ete
# lues dans Wireshark (paquet [SYN, ACK] > Internet Protocol > Time to Live).
TTL_WIRESHARK = {
    "41.106.128.70": 52,    # www.usthb.dz
    "210.152.243.234": 48,  # www.u-tokyo.ac.jp
    "200.144.235.134": 51,  # www.usp.br
}

NB_ESSAIS = 3
TIMEOUT = 2.0
TTL_ENVOI = 64


def ip_locale(dest_ip):
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.connect((dest_ip, 80))
    local = tmp.getsockname()[0]
    tmp.close()
    return local


def ouvrir_raw(local, proto):
    """Socket raw lie a l'adresse locale. Sous Windows : SIO_RCVALL.

    ICMP : on garde le protocole ICMP (sinon l'envoi du ping ne marche pas).
    TCP  : on ne fait que lire, donc IPPROTO_IP sous Windows.
    """
    windows = hasattr(socket, "SIO_RCVALL")
    if windows and proto == socket.IPPROTO_TCP:
        proto = socket.IPPROTO_IP
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    s.bind((local, 0))
    if windows:
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return s


# ---------- Methode 1 : ICMP ----------

def ping(sock, dest_ip, ident, seq):
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL_ENVOI)
    t0 = time.perf_counter()
    sock.sendto(build_echo(ident, seq), (dest_ip, 0))
    fin = t0 + TIMEOUT
    while True:
        restant = fin - time.perf_counter()
        if restant <= 0:
            return None
        pret, _, _ = select.select([sock], [], [], restant)
        if not pret:
            return None
        data, addr = sock.recvfrom(2048)
        t1 = time.perf_counter()
        if len(data) < 28 or data[9] != 1:
            continue
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 8 or data[ihl] != 0:
            continue
        r_id, r_seq = struct.unpack("!HH", data[ihl + 4:ihl + 8])
        if addr[0] == dest_ip and r_id == ident and r_seq == seq:
            return data[8], (t1 - t0) * 1000.0


def mesurer_icmp(ip):
    sock = ouvrir_raw(ip_locale(ip), socket.IPPROTO_ICMP)
    ident = (int(time.time()) ^ 0x1234) & 0xFFFF
    meilleur = None
    for i in range(NB_ESSAIS):
        res = ping(sock, ip, ident, i + 1)
        if res and (meilleur is None or res[1] < meilleur[1]):
            meilleur = res
    sock.close()
    if meilleur is None:
        return None
    return meilleur[0], meilleur[1], "ICMP"


# ---------- Methode 2 : TCP ----------

def lire_synack(sniff, ip, port):
    """Lit les paquets recus et retourne le TTL du SYN-ACK venant de ip:port."""
    ttl = None
    vus = 0
    total = 0
    fin = time.perf_counter() + 0.5
    while time.perf_counter() < fin:
        pret, _, _ = select.select([sniff], [], [], 0.2)
        if not pret:
            break
        data, addr = sniff.recvfrom(65535)
        total += 1
        if len(data) < 20 or data[9] != 6 or addr[0] != ip:
            continue
        vus += 1
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 14:
            continue
        sport = struct.unpack("!H", data[ihl:ihl + 2])[0]
        flags = data[ihl + 13]
        if sport == port and (flags & 0x12) == 0x12:  # SYN + ACK
            ttl = data[8]
    return ttl, vus, total


def mesurer_tcp(ip):
    sniff = ouvrir_raw(ip_locale(ip), socket.IPPROTO_TCP)
    meilleur = None
    for port in (443, 80):
        for _ in range(NB_ESSAIS):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            t0 = time.perf_counter()
            try:
                s.connect((ip, port))
            except OSError:
                s.close()
                continue
            rtt = (time.perf_counter() - t0) * 1000.0
            s.close()
            ttl, _, _ = lire_synack(sniff, ip, port)
            if meilleur is None or rtt < meilleur[1]:
                meilleur = (ttl, rtt, f"TCP:{port}")
        if meilleur:
            break
    sniff.close()
    return meilleur


def ttl_initial(ttl):
    for v in (32, 64, 128, 255):
        if ttl <= v:
            return v
    return 255


def main():
    lignes = [f"{'hote':22} {'IP':16} {'methode':8} {'TTL':>4} {'sauts':>6} {'RTT ms':>8} {'km max':>7}"]
    for hote in HOTES:
        try:
            ip = socket.gethostbyname(hote)
            res = mesurer_icmp(ip)
            if res is None:
                res = mesurer_tcp(ip)
        except OSError as e:
            lignes.append(f"{hote:22} erreur : {e}")
            continue
        if res is None:
            lignes.append(f"{hote:22} {ip:16} aucune reponse (ICMP et TCP)")
            continue
        ttl, rtt, methode = res
        km_max = rtt * 100  # lumiere dans la fibre : 200 km/ms, aller-retour
        note = ""
        if ttl is None and ip in TTL_WIRESHARK:
            ttl = TTL_WIRESHARK[ip]
            note = "  (TTL lu dans Wireshark)"
        if ttl is None:
            lignes.append(f"{hote:22} {ip:16} {methode:8} {'?':>4} {'?':>6} {rtt:>8.1f} {km_max:>7.0f}"
                          "  TTL a lire dans Wireshark")
            continue
        sauts = ttl_initial(ttl) - ttl + 1
        lignes.append(f"{hote:22} {ip:16} {methode:8} {ttl:>4} {sauts:>6} {rtt:>8.1f} {km_max:>7.0f}{note}")
    texte = "\n".join(lignes)
    print(texte)
    with open("step1.txt", "w", encoding="utf-8") as f:
        f.write(texte + "\n")


if __name__ == "__main__":
    main()
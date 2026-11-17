#!/usr/bin/env python3
"""traceroute.py : traceroute ICMP avec socket raw.

Usage (en administrateur) :
    python traceroute.py www.univ-bejaia.dz
"""
import argparse
import select
import socket
import struct
import time

from trace_map import draw_map

# A MODIFIER : ton prenom et ton nom, sans accents.
PRENOM_NOM = "BERRICHI ADEL"

# A MODIFIER : ta position (latitude, longitude).
SOURCE_DEFAUT = (35.70, -0.63)

MAX_TTL = 30
NB_SONDES = 3
TIMEOUT = 2.0


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo(ident, seq):
    payload = PRENOM_NOM.encode("ascii")
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    csum = checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, csum, ident, seq)
    return header + payload


def probe(sock, dest_ip, ttl, ident, seq):
    """Envoie une sonde. Retourne (ip, rtt_ms, type_icmp) ou None."""
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    t0 = time.perf_counter()
    sock.sendto(build_echo(ident, seq), (dest_ip, 0))
    deadline = t0 + TIMEOUT
    while True:
        restant = deadline - time.perf_counter()
        if restant <= 0:
            return None
        pret, _, _ = select.select([sock], [], [], restant)
        if not pret:
            return None
        data, addr = sock.recvfrom(2048)
       
        t1 = time.perf_counter()
        if len(data) < 28 or data[9] != 1:  # on garde seulement ICMP
            continue
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 8:
            continue
        typ = data[ihl]
        if typ == 0:  # echo reply
            r_id, r_seq = struct.unpack("!HH", data[ihl + 4:ihl + 8])
        elif typ in (3, 11):  # unreachable / time exceeded
            inner = ihl + 8
            if len(data) < inner + 28:
                continue
            inner_ihl = (data[inner] & 0x0F) * 4
            icmp_in = inner + inner_ihl
            if len(data) < icmp_in + 8:
                continue
            r_id, r_seq = struct.unpack("!HH", data[icmp_in + 4:icmp_in + 8])
        else:
            continue
        if r_id == ident and r_seq == seq:
            return addr[0], (t1 - t0) * 1000.0, typ


def nom_inverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ip


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--source", help="latitude,longitude de la source")
    args = ap.parse_args()

    source = SOURCE_DEFAUT
    if args.source:
        lat, lon = args.source.split(",")
        source = (float(lat), float(lon))

    dest_ip = socket.gethostbyname(args.host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.connect((dest_ip, 80))
    sock.bind((tmp.getsockname()[0], 0))
    if hasattr(socket, "SIO_RCVALL"):  # Windows seulement
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    ident = (int(time.time()) ^ 0x5A5A) & 0xFFFF
    seq = 0

    lignes = [f"traceroute vers {args.host} ({dest_ip}), {MAX_TTL} sauts max, "
              f"{NB_SONDES} sondes par TTL"]
    print(lignes[0])
    hops = []
    arrive = False

    for ttl in range(1, MAX_TTL + 1):
        rtts, ips = [], []
        for _ in range(NB_SONDES):
            seq += 1
            res = probe(sock, dest_ip, ttl, ident, seq)
            if res is None:
                rtts.append(None)
            else:
                ip, rtt, typ = res
                rtts.append(rtt)
                ips.append((rtt, ip))
                if typ == 0 or typ == 3:
                    arrive = True

        if ips:
            meilleur_rtt, ip = min(ips)
            nom = nom_inverse(ip)
            hops.append((ttl, ip, meilleur_rtt))
            texte = "  ".join("*" if r is None else f"{r:.1f} ms" for r in rtts)
            ligne = f"{ttl:2d}  {ip}  ({nom})  {texte}"
        else:
            hops.append((ttl, None, None))
            ligne = f"{ttl:2d}  *  *  *"
        print(ligne)
        lignes.append(ligne)
        if arrive:
            break

    with open(f"{args.host}.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lignes) + "\n")

    draw_map(args.host, hops, f"{args.host}.html", source)
    print(f"Fichiers ecrits : {args.host}.txt et {args.host}.html")


if __name__ == "__main__":
    main()
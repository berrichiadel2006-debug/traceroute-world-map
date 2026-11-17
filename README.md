# Traceroute sur une carte du monde

Projet de cours (Advanced Networks, ING3 SD, USTO-MB). Un traceroute écrit en Python avec des sockets, qui dessine le chemin des paquets sur une carte du monde.

## Comment ça marche
- Envoie 3 sondes ICMP pour chaque TTL (de 1 à 30)
- Lit les réponses ICMP des routeurs
- Affiche l'adresse, le nom DNS et le RTT de chaque routeur
- Dessine le chemin sur une carte avec `trace_map.py`

## Lancer
Python 3 seulement, sans module externe. Il faut les droits administrateur (socket brut).

    python traceroute.py www.ethz.ch

## Fichiers
- `traceroute.py` : le programme
- `step1.py` : mesure le TTL et le RTT pour reconnaître les CDN
- `trace_map.py` : dessine la carte (fourni par le professeur)
- `www.*.txt`, `.pcapng`, `.html` : sortie, capture Wireshark et carte de chaque hôte
- `rapport_traceroute.pdf.pdf` : le rapport

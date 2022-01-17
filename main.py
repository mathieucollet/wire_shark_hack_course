import csv
import hashlib

from scapy.all import *
from scapy.layers.inet import TCP, IP

passwords = [
    "azerty",
    "admin",
    "root",
    "Hello",
    "Aloha",
    "mypassword,"
    "1234,"
    "Thatsme",
]


def hack(hashed_password):
    hashed_password_len = len(hashed_password)
    hash_type = ""
    for password in passwords:
        if hashed_password_len == 32:
            hash_type = "md5"
            if hashed_password == hashlib.md5(password.encode('utf-8')).hexdigest():
                return password, hash_type
        elif hashed_password_len == 40:
            hash_type = "sha1"
            if hashed_password == hashlib.sha1(password.encode('utf-8')).hexdigest():
                return password, hash_type
        elif hashed_password_len == 64:
            hash_type = "sha256"
            if hashed_password == hashlib.sha256(password.encode('utf-8')).hexdigest():
                return password, hash_type
    return None, hash_type


def read_pcap(pcap):
    hosts = {}
    for p in pcap:
        if p.haslayer(IP):
            if p[IP].src not in hosts:
                hosts[p[IP].src] = []
            hosts[p[IP].src].append(p)
    return hosts


def get_hash_string(string):
    return string.split("hash")[1].split("\"")[2]


def get_login_string(string):
    return string.split("login")[2].split("\"")[2]


def hack_password_in_pcap(pcapng_file):
    hosts = read_pcap(pcapng_file)
    data = []
    for host in hosts:
        for request in hosts[host]:
            if request.haslayer(TCP) and request[TCP].dport == 80 and request.haslayer(Raw):
                decoded_content = request[Raw].load.decode('utf-8')
                if "hash" in decoded_content:
                    password, hash_type = hack(get_hash_string(decoded_content))
                    if "login" in decoded_content:
                        data.append(
                            {
                                "login": get_login_string(decoded_content),
                                "password": password,
                                "hash_type": hash_type,
                                "ip": host,
                                "port": request[TCP].sport
                            }
                        )
    with open("results.csv", "w", encoding="UTF-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys(), delimiter=";")
        writer.writeheader()
        writer.writerows(data)


def main():
    pcapng_file = rdpcap("logs.pcapng")
    hack_password_in_pcap(pcapng_file)


if __name__ == "__main__":
    main()

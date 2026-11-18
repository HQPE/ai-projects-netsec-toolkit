#!/usr/bin/env python3
"""
NetSec Toolkit - IT, ağ ve siber güvenlik için küçük araçlar.

Modüller:
  subnet   CIDR / alt ağ hesaplayıcı
  scan     TCP port tarayıcı (sadece izinli olduğun sistemlerde kullan!)
  logscan  SSH auth.log analizi, brute-force tespiti
  hash     Dosya hash hesaplama ve doğrulama

Sadece Python standart kütüphanesini kullanır.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import re
import socket
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------- subnet

def subnet_info(cidr: str) -> dict:
    """Verilen CIDR için alt ağ bilgilerini döndürür."""
    iface = ipaddress.ip_interface(cidr.strip())
    net = iface.network
    info = {
        "input": str(iface.ip),
        "network": str(net.network_address),
        "prefix": net.prefixlen,
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "version": net.version,
        "total_addresses": net.num_addresses,
        "private": net.is_private,
    }
    if net.version == 4:
        info["broadcast"] = str(net.broadcast_address)
        if net.prefixlen >= 31:  # /31 (RFC 3021) ve /32 özel durum
            info["first_host"] = str(net.network_address)
            info["last_host"] = str(net.broadcast_address)
            info["usable_hosts"] = net.num_addresses
        else:
            info["first_host"] = str(net.network_address + 1)
            info["last_host"] = str(net.broadcast_address - 1)
            info["usable_hosts"] = net.num_addresses - 2
        first_octet = int(str(net.network_address).split(".")[0])
        info["class"] = ("A" if first_octet < 128 else "B" if first_octet < 192
                         else "C" if first_octet < 224 else "D (multicast)"
                         if first_octet < 240 else "E (reserved)")
    else:
        info["first_host"] = str(net.network_address)
        info["last_host"] = str(net.broadcast_address)
        info["usable_hosts"] = net.num_addresses
    return info


def split_subnet(cidr: str, new_prefix: int) -> list[str]:
    """Bir ağı daha küçük alt ağlara böler."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    if new_prefix <= net.prefixlen:
        raise ValueError("Yeni prefix mevcut prefix'ten büyük olmalı.")
    if new_prefix - net.prefixlen > 12:
        raise ValueError("En fazla 4096 alt ağa bölünebilir.")
    return [str(s) for s in net.subnets(new_prefix=new_prefix)]


# ---------------------------------------------------------------- port scan

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
                995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]


def parse_ports(spec: str) -> list[int]:
    """'22,80,8000-8010' veya 'common' biçimindeki port listesini çözer."""
    if spec.strip().lower() == "common":
        return list(COMMON_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Geçersiz port: {bad[0]} (1-65535 olmalı)")
    return sorted(ports)


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def check_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(host: str, ports: list[int], timeout: float = 0.5,
               workers: int = 100) -> list[int]:
    """Açık TCP portlarının listesini döndürür (TCP connect taraması)."""
    ip = socket.gethostbyname(host)
    with ThreadPoolExecutor(max_workers=min(workers, len(ports) or 1)) as ex:
        results = ex.map(lambda p: (p, check_port(ip, p, timeout)), ports)
        return [p for p, ok in results if ok]


# ---------------------------------------------------------------- log scan

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)


def analyze_auth_log(lines, threshold: int = 5) -> dict:
    """auth.log satırlarından başarısız/başarılı SSH girişlerini çıkarır."""
    failed_ips: Counter = Counter()
    failed_users: Counter = Counter()
    invalid_users: Counter = Counter()
    accepted: list[tuple[str, str]] = []
    for line in lines:
        if m := FAILED_RE.search(line):
            failed_ips[m["ip"]] += 1
            failed_users[m["user"]] += 1
        elif m := INVALID_RE.search(line):
            invalid_users[m["user"]] += 1
        elif m := ACCEPTED_RE.search(line):
            accepted.append((m["user"], m["ip"]))
    suspicious = {ip: n for ip, n in failed_ips.items() if n >= threshold}
    # Önce başarısız deneme yapıp sonra giriş yapan IP'ler: olası ele geçirme
    compromised = sorted({(u, ip) for u, ip in accepted if ip in suspicious})
    return {
        "total_failed": sum(failed_ips.values()),
        "unique_ips": len(failed_ips),
        "top_ips": failed_ips.most_common(10),
        "top_users": failed_users.most_common(10),
        "invalid_users": invalid_users.most_common(10),
        "accepted": accepted,
        "suspicious": dict(sorted(suspicious.items(), key=lambda x: -x[1])),
        "possible_compromise": compromised,
    }


# ---------------------------------------------------------------- hash

ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]


def file_hash(path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def text_hash(text: str, algo: str = "sha256") -> str:
    return hashlib.new(algo, text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- CLI

def cmd_subnet(a) -> int:
    info = subnet_info(a.cidr)
    labels = {
        "input": "Girilen IP", "network": "Ağ adresi", "prefix": "Prefix",
        "netmask": "Alt ağ maskesi", "wildcard": "Wildcard maske",
        "broadcast": "Broadcast", "first_host": "İlk host", "last_host": "Son host",
        "usable_hosts": "Kullanılabilir host", "total_addresses": "Toplam adres",
        "class": "Sınıf", "private": "Özel (private) ağ", "version": "IP sürümü",
    }
    for k, label in labels.items():
        if k in info:
            v = info[k]
            v = "Evet" if v is True else "Hayır" if v is False else v
            print(f"{label:<22}: {v}")
    if a.split:
        print(f"\n/{a.split} alt ağları:")
        for s in split_subnet(a.cidr, a.split):
            print("  " + s)
    return 0


def cmd_scan(a) -> int:
    ports = parse_ports(a.ports)
    print(f"[*] {a.host} taranıyor ({len(ports)} port)...")
    open_ports = scan_ports(a.host, ports, a.timeout, a.workers)
    if not open_ports:
        print("[-] Açık port bulunamadı.")
    for p in open_ports:
        print(f"[+] {p:>5}/tcp  açık   {service_name(p)}")
    return 0


def cmd_logscan(a) -> int:
    with open(a.file, encoding="utf-8", errors="replace") as f:
        r = analyze_auth_log(f, a.threshold)
    print(f"Başarısız giriş   : {r['total_failed']}")
    print(f"Farklı IP         : {r['unique_ips']}")
    print("\nEn çok deneyen IP'ler:")
    for ip, n in r["top_ips"]:
        flag = "  <-- ŞÜPHELİ" if ip in r["suspicious"] else ""
        print(f"  {ip:<18} {n:>5}{flag}")
    print("\nEn çok denenen kullanıcılar:")
    for u, n in r["top_users"]:
        print(f"  {u:<18} {n:>5}")
    print(f"\nBaşarılı girişler : {len(r['accepted'])}")
    for u, ip in r["accepted"]:
        print(f"  {u}@{ip}")
    if r["possible_compromise"]:
        print("\n[!] UYARI: Brute-force yapan IP'den başarılı giriş:")
        for u, ip in r["possible_compromise"]:
            print(f"  {u} <- {ip}")
    return 1 if r["possible_compromise"] else 0


def cmd_hash(a) -> int:
    algos = ALGORITHMS if a.algo == "all" else [a.algo]
    if a.verify and len(algos) != 1:
        print("Hata: --verify için tek bir algoritma seç.", file=sys.stderr)
        return 2
    for algo in algos:
        digest = text_hash(a.target, algo) if a.text else file_hash(a.target, algo)
        print(f"{algo:<7} {digest}")
        if a.verify:
            ok = digest.lower() == a.verify.strip().lower()
            print("[+] Eşleşiyor, dosya sağlam." if ok else "[-] EŞLEŞMİYOR!")
            return 0 if ok else 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netsec",
                                description="IT / ağ / siber güvenlik araç seti")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("subnet", help="CIDR / alt ağ hesaplayıcı")
    s.add_argument("cidr", help="Örn: 192.168.1.10/24")
    s.add_argument("--split", type=int, metavar="PREFIX",
                   help="Ağı bu prefix'e göre alt ağlara böl (örn: 26)")
    s.set_defaults(func=cmd_subnet)

    s = sub.add_parser("scan", help="TCP port tarayıcı")
    s.add_argument("host", help="Hedef host / IP (izinli olduğun sistemler!)")
    s.add_argument("-p", "--ports", default="common",
                   help="'common', '22,80,443' veya '1-1024' (varsayılan: common)")
    s.add_argument("-t", "--timeout", type=float, default=0.5)
    s.add_argument("-w", "--workers", type=int, default=100)
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("logscan", help="SSH auth.log analizi")
    s.add_argument("file", help="Örn: /var/log/auth.log")
    s.add_argument("--threshold", type=int, default=5,
                   help="Şüpheli sayılacak başarısız deneme sayısı (varsayılan: 5)")
    s.set_defaults(func=cmd_logscan)

    s = sub.add_parser("hash", help="Hash hesaplama / doğrulama")
    s.add_argument("target", help="Dosya yolu (veya --text ile metin)")
    s.add_argument("-a", "--algo", default="sha256", choices=ALGORITHMS + ["all"])
    s.add_argument("--text", action="store_true", help="Hedefi metin olarak işle")
    s.add_argument("--verify", metavar="HASH", help="Beklenen hash ile karşılaştır")
    s.set_defaults(func=cmd_hash)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as e:
        print(f"Hata: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

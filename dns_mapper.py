import argparse
import dns.resolver
import dns.reversename
import re
import json

# =========================
# CONFIG
# =========================

dns.resolver.timeout = 2
dns.resolver.lifetime = 2

SRV_SERVICES = [
    "_sip._tcp",
    "_sip._udp",
    "_xmpp-server._tcp",
    "_xmpp-client._tcp",
    "_ldap._tcp",
    "_imaps._tcp",
    "_submission._tcp",
]

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev", "test",
    "staging", "preprod", "admin", "vpn",
    "blog", "shop"
]

KNOWN_TLDS = {
    "com", "net", "org", "fr", "co.uk", "gouv.fr"
}

# =========================
# ARGUMENTS
# =========================

def parse_args():
    parser = argparse.ArgumentParser(description="DNS Mapper (DNS only)")
    parser.add_argument("domainName", help="Nom de domaine à analyser")
    parser.add_argument("-o", "--output", help="Fichier de sortie JSON")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Profondeur de récursion")
    parser.add_argument("-n", "--neighbour", type=int, default=2, help="Nombre d'IP voisines à scanner (default: 2)")
    parser.add_argument("-s", "--subdomain", action="store_true", help="Activer la subdomain enumeration")
    return parser.parse_args()

# =========================
# DNS RESOLUTION
# =========================

def resolve_records(domain):
    records = {}
    for rtype in ["A", "AAAA", "CNAME", "MX", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [a.to_text() for a in answers]
        except Exception:
            records[rtype] = []
    return records

# =========================
# STRATEGIES
# =========================

def generic_strategy(dns_records):
    domains = set()
    ips = set()

    for records in dns_records.values():
        for r in records:
            r = strip_trailing_dot(r)
            domains |= extract_domains(r)
            ips |= extract_ips(r)

    return domains, ips

def srv_strategy(domain):
    found = set()
    for service in SRV_SERVICES:
        try:
            answers = dns.resolver.resolve(f"{service}.{domain}", "SRV")
            for r in answers:
                found.add(strip_trailing_dot(str(r.target)))
        except Exception:
            pass
    return found

def crawl_to_tld(domain):
    parts = domain.split(".")
    found = set()
    for i in range(1, len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in KNOWN_TLDS:
            break
        found.add(candidate)
    return found

def subdomain_strategy(domain):
    return {f"{s}.{domain}" for s in COMMON_SUBDOMAINS}

def reverse_dns(ip):
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR")
        return {strip_trailing_dot(a.to_text()) for a in answers}
    except Exception:
        return set()

def ip_neighbors(ip, radius):
    found = set()
    parts = ip.split(".")
    if len(parts) != 4:
        return found

    try:
        base = int(parts[-1])
    except ValueError:
        return found

    for offset in range(-radius, radius + 1):
        if offset == 0:
            continue
        n = base + offset
        if 0 <= n <= 255:
            neighbor = ".".join(parts[:-1] + [str(n)])
            found |= reverse_dns(neighbor)

    return found

# =========================
# HELPERS
# =========================

def extract_domains(text):
    return set(re.findall(
        r"(?:[a-z0-9-]+\.)+[a-z]{2,}",
        text,
        flags=re.IGNORECASE
    ))

def extract_ips(text):
    return set(re.findall(
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        text
    ))

def strip_trailing_dot(domain):
    return domain[:-1] if domain.endswith(".") else domain

# =========================
# OUTPUT
# =========================

def show_result_terminal(results_by_depth):
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    record_icons = {
        "A": "🌐",
        "AAAA": "🔗",
        "CNAME": "🔀",
        "MX": "📧",
        "TXT": "📝",
        "SRV": "🔧"
    }
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV"]

    total_domains = sum(len(domains) for domains in results_by_depth.values())
    
    print(f"\n{BOLD}{CYAN}╔{'═'*78}╗{END}")
    print(f"{BOLD}{CYAN}║{'DNS MAPPER RESULTS':^78}║{END}")
    print(f"{BOLD}{CYAN}║{f'Total domains scanned: {total_domains}':^78}║{END}")
    print(f"{BOLD}{CYAN}╚{'═'*78}╝{END}")

    for depth, domains_list in results_by_depth.items():
        if not domains_list:
            continue
            
        print(f"\n{BOLD}{YELLOW}┌{'─'*78}┐{END}")
        print(f"{BOLD}{YELLOW}│{'🔍 DEPTH ' + str(depth):^77}│{END}")
        print(f"{BOLD}{YELLOW}└{'─'*78}┘{END}")

        for i, info in enumerate(domains_list):
            domain = info['DNS']
            print(f"\n{BOLD}{GREEN}  ┌── 🌍 {domain}{END}")
            print(f"{GREEN}  │{END}")

            for rt in record_types:
                icon = record_icons.get(rt, "•")
                records = info.get(rt, [])
                
                has_records = records and len(records) > 0
                
                if has_records:
                    print(f"{GREEN}  │  {BOLD}{BLUE}{icon} {rt}:{END}")
                    for r in records:
                        print(f"{GREEN}  │     {CYAN}└─ {r}{END}")
                else:
                    print(f"{GREEN}  │  {RED}{icon} {rt}: ✗ Non trouvé{END}")
            
            print(f"{GREEN}  └{'─'*40}{END}")


def export_json(results, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

# =========================
# MAIN
# =========================

def main():
    args = parse_args()

    visited = set()
    current_domains = {args.domainName}
    results = {}

    depth = 1
    while current_domains and depth <= args.depth:
        results[depth] = []
        next_domains = set()

        for domain in current_domains:
            domain = strip_trailing_dot(domain)
            
            if domain in visited:
                continue
            
            print(f"[Depth {depth}] Scanning: {domain}")
            visited.add(domain)

            dns_records = resolve_records(domain)
            entry = {"DNS": domain, **dns_records}
            results[depth].append(entry)

            new_domains, ips = generic_strategy(dns_records)
            next_domains |= new_domains
            next_domains |= srv_strategy(domain)
            next_domains |= crawl_to_tld(domain)

            if args.subdomain:
                next_domains |= subdomain_strategy(domain)

            for ip in ips:
                next_domains |= reverse_dns(ip)
                next_domains |= ip_neighbors(ip, args.neighbour)

        current_domains = next_domains
        depth += 1

    show_result_terminal(results)

    if args.output:
        export_json(results, args.output)

if __name__ == "__main__":
    main()

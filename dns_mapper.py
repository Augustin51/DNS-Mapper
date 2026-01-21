import argparse
import dns.resolver
import dns.reversename
import re
import json

# =========================
# CONFIGURATION
# =========================

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
    "staging", "preprod", "intra",
    "admin", "vpn", "blog", "shop"
]

KNOWN_TLDS = {
    "com", "net", "org", "fr", "co.uk", "gouv.fr"
}

# =========================
# ARGUMENTS
# =========================

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domainName")
    parser.add_argument("--output", "-o", type=str)
    parser.add_argument("--depth", "-d", type=int, default=5)
    return parser.parse_args()

# =========================
# DNS RESOLUTION
# =========================

def resolve_records(domain):
    result = {}
    for record_type in ["A", "AAAA", "CNAME", "MX", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result[record_type] = [r.to_text() for r in answers]
        except Exception:
            result[record_type] = []
    return result

# =========================
# STRATÉGIES
# =========================

def generic_strategy(dns_records):
    domains = set()
    ips = set()

    for records in dns_records.values():
        for r in records:
            r = strip_trailing_dot(r)
            domains.update(extract_domains(r))
            ips.update(extract_ips(r))

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
    return {f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS}

def reverse_dns(ip):
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR")
        return {strip_trailing_dot(r.to_text()) for r in answers}
    except Exception:
        return set()

def ip_neighbors(ip):
    found = set()
    parts = ip.split(".")
    if len(parts) != 4:
        return found

    base = int(parts[-1])
    for offset in [-1, 1]:
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

def strip_trailing_dot(d):
    return d[:-1] if d.endswith(".") else d

# =========================
# OUTPUT
# =========================

def show_result_terminal(results):
    for depth, entries in results.items():
        print(f"\n=== DEPTH {depth} ===")
        for entry in entries:
            print(f"\n🌍 {entry['DNS']}")
            for rt, values in entry.items():
                if rt == "DNS":
                    continue
                if values:
                    for v in values:
                        print(f"  {rt}: {v}")

def export_json(results, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

# =========================
# MAIN
# =========================

def main():
    args = parse_args()

    visited = set()
    current = {args.domainName}
    results = {}

    depth = 1
    while current and depth <= args.depth:
        results[depth] = []
        next_domains = set()

        for domain in current:
            domain = strip_trailing_dot(domain)
            if domain in visited:
                continue
            visited.add(domain)

            dns_records = resolve_records(domain)
            entry = {"DNS": domain, **dns_records}

            results[depth].append(entry)

            # STRATÉGIES
            new_domains, ips = generic_strategy(dns_records)
            next_domains |= new_domains
            next_domains |= srv_strategy(domain)
            next_domains |= crawl_to_tld(domain)
            next_domains |= subdomain_strategy(domain)

            for ip in ips:
                next_domains |= reverse_dns(ip)
                next_domains |= ip_neighbors(ip)

        current = next_domains
        depth += 1

    show_result_terminal(results)

    if args.output:
        export_json(results, args.output)

if __name__ == "__main__":
    main()

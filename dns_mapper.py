import argparse
import dns.resolver
import dns.reversename
import re

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domainName")
    parser.add_argument("--output", "-o", type=str)
    parser.add_argument("--depth", "-d", type=int, default=5)
    args = parser.parse_args()
    return args

def resolve_records(domain):
    result = {}
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result[record_type] = [rdata.to_text() for rdata in answers]
        except:
            result[record_type] = [f"No {record_type} record found"]

    return result

def parse_dns_records(dns_records):
    new_domains = []
    new_IPs = []
    
    for d in dns_records:
        dns_record = dns_records[d]
        for dns in dns_record :
            dns = strip_trailing_dot(dns)
            new_domains.extend(extract_new_domain(dns))
            new_IPs.extend(extract_new_ip(dns))

    return new_domains, new_IPs

def extract_new_domain(dns_record):
    return re.findall(
        rf"(?:[a-z0-9_]" + 
        rf"(?:[a-z0-9-_]{{0,61}}" + 
        rf"[a-z0-9_])?\.)" + 
        r"+[a-z0-9][a-z0-9-_]{0,61}" + 
        rf"[a-z]\.?",
        dns_record,
        flags=re.IGNORECASE,
    )

def extract_new_ip(dns_record):
    return re.findall(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        dns_record,
        flags=re.IGNORECASE,
    )

def reverse_dns(ip):
    try:
        reversed_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(reversed_name, "PTR")
        return [strip_trailing_dot(rdata.to_text()) for rdata in answers]
    except Exception:
        return []

def strip_trailing_dot(domain):
    if domain.endswith('.'):
        return domain[:-1]
    return domain

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
        "TXT": "📝"
    }
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT"]

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
                
                has_records = records and not any("No " in r for r in records)
                
                if has_records:
                    print(f"{GREEN}  │  {BOLD}{BLUE}{icon} {rt}:{END}")
                    for r in records:
                        print(f"{GREEN}  │     {CYAN}└─ {r}{END}")
                else:
                    print(f"{GREEN}  │  {RED}{icon} {rt}: ✗ Non trouvé{END}")
            
            print(f"{GREEN}  └{'─'*40}{END}")



def main():
    args = parse_args()

    results_by_depth = {}
    visited = set()

    current_domains = {args.domainName}
    depth = 1
    max_depth = args.depth

    while current_domains and depth <= max_depth:
        results_by_depth[depth] = []
        next_domains = set()

        for domain in current_domains:
            domain = strip_trailing_dot(domain)
            if domain in visited:
                continue
            visited.add(domain)

            dns_result = resolve_records(domain)
            results_by_depth[depth].append({
                "DNS": domain,
                **dns_result
            })

            new_domains, new_IPs = parse_dns_records(dns_result)
            next_domains.update(new_domains)

            for ip in new_IPs:
                next_domains.update(reverse_dns(ip))

        current_domains = next_domains
        depth += 1
    show_result_terminal(results_by_depth)


if __name__ == "__main__":
    main()

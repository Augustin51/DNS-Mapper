import argparse
import dns.resolver
import dns.reversename
import re
import json

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domainName")
    parser.add_argument("--output", "-o", type=str)
    parser.add_argument("--depth", "-d", type=int, default=5)
    args = parser.parse_args()
    return args

def resolve_records(domain):
    result = {}
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV']
    
    # Services SRV courants à scanner
    srv_prefixes = [
        '_sip._tcp', '_sip._udp', '_xmpp-server._tcp', '_xmpp-client._tcp',
        '_ldap._tcp', '_kerberos._tcp', '_kerberos._udp', '_http._tcp',
        '_https._tcp', '_imaps._tcp', '_pop3s._tcp', '_submission._tcp'
    ]

    for record_type in record_types:
        if record_type == 'SRV':
            srv_records = []
            for prefix in srv_prefixes:
                try:
                    srv_domain = f"{prefix}.{domain}"
                    answers = dns.resolver.resolve(srv_domain, 'SRV')
                    for rdata in answers:
                        srv_records.append(f"{prefix}: {rdata.priority} {rdata.weight} {rdata.port} {rdata.target}")
                except:
                    pass
            result['SRV'] = srv_records if srv_records else ["No SRV record found"]
        else:
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
        answers = dns.resolver.resolve(reversed_name, ".")
        return [strip_trailing_dot(rdata.to_text()) for rdata in answers]
    except Exception:
        return []

def strip_trailing_dot(domain):
    if domain.endswith('.'):
        return domain[:-1]
    return domain

def extract_parent_domains(domain):
    common_tlds = {
        'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'fr', 'de', 'uk', 'eu',
        'app', 'dev', 'cloud', 'tech', 'info', 'biz', 'xyz', 'online', 'site',
        'me', 'tv', 'cc', 'us', 'ca', 'au', 'jp', 'cn', 'ru', 'br', 'in'
    }
    compound_tlds = {
        'co.uk', 'com.au', 'co.jp', 'com.br', 'co.in', 'org.uk', 'net.au',
        'ac.uk', 'gov.uk', 'org.au', 'com.cn', 'com.mx', 'co.nz', 'com.ar'
    }
    
    parts = domain.lower().split('.')
    parent_domains = []
    
    if len(parts) <= 2:
        return parent_domains
    
    is_compound = False
    if len(parts) >= 2:
        potential_compound = f"{parts[-2]}.{parts[-1]}"
        if potential_compound in compound_tlds:
            is_compound = True
    
    min_parts = 3 if is_compound else 2
    
    for i in range(1, len(parts) - min_parts + 1):
        parent = '.'.join(parts[i:])
        if parent and parent != domain:
            parent_domains.append(parent)
    
    return parent_domains

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
                
                has_records = records and not any("No " in r for r in records)
                
                if has_records:
                    print(f"{GREEN}  │  {BOLD}{BLUE}{icon} {rt}:{END}")
                    for r in records:
                        print(f"{GREEN}  │     {CYAN}└─ {r}{END}")
                else:
                    print(f"{GREEN}  │  {RED}{icon} {rt}: ✗ Non trouvé{END}")
            
            print(f"{GREEN}  └{'─'*40}{END}")

def show_result_output(results_by_depth, output_file):
    extension = output_file.lower().split('.')[-1]
    
    if extension == 'json':
        export_json(results_by_depth, output_file)
    elif extension == 'txt':
        export_txt(results_by_depth, output_file)
    else:
        print(f"Format non supporté: {extension}. Utilisez .json ou .txt")
        return
    
    print(f"Résultats exportés vers: {output_file}")

def export_json(results_by_depth, output_file):
    output_data = {}
    
    for depth, domains_list in results_by_depth.items():
        output_data[f"depth_{depth}"] = []
        for info in domains_list:
            domain_data = {
                "domain": info['DNS'],
                "records": {}
            }
            for rt in ["A", "AAAA", "CNAME", "MX", "TXT", "SRV"]:
                records = info.get(rt, [])
                has_records = records and not any("No " in r for r in records)
                domain_data["records"][rt] = records if has_records else []
            output_data[f"depth_{depth}"].append(domain_data)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

def export_txt(results_by_depth, output_file):
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV"]
    total_domains = sum(len(domains) for domains in results_by_depth.values())
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write(f"{'DNS MAPPER RESULTS':^80}\n")
        f.write(f"{'Total domains scanned: ' + str(total_domains):^80}\n")
        f.write("=" * 80 + "\n\n")
        
        for depth, domains_list in results_by_depth.items():
            if not domains_list:
                continue
            
            f.write("-" * 80 + "\n")
            f.write(f"{'DEPTH ' + str(depth):^80}\n")
            f.write("-" * 80 + "\n\n")
            
            for info in domains_list:
                domain = info['DNS']
                f.write(f"Domain: {domain}\n")
                f.write("-" * 40 + "\n")
                
                for rt in record_types:
                    records = info.get(rt, [])
                    has_records = records and not any("No " in r for r in records)
                    
                    if has_records:
                        f.write(f"  {rt}:\n")
                        for r in records:
                            f.write(f"    - {r}\n")
                    else:
                        f.write(f"  {rt}: Non trouvé\n")
                
                f.write("\n")



def main():
    args = parse_args()

    results_by_depth = {}
    visited = set()

    current_domains = {args.domainName}
    
    parent_domains = extract_parent_domains(args.domainName)
    current_domains.update(parent_domains)
    
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
    
    if args.output:
        show_result_output(results_by_depth, args.output)


if __name__ == "__main__":
    main()

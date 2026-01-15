import argparse
import dns.resolver
import dns.reversename
import re

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domainName")
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
        return [rdata.to_text().rstrip('.') for rdata in answers]
    except Exception:
        return []

def show_result(results_by_depth):
    for d, domains_list in results_by_depth.items():
        print(f"\n=== Depth {d} ===")
        for info in domains_list:
            print(f"DNS: {info['DNS']}")
            for rec_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
                print(f"{rec_type}: {info[rec_type]}")

def main():
    args = parse_args()

    results_by_depth = {}
    visited = set()

    current_domains = {args.domainName}
    depth = 1
    max_depth = 10

    while current_domains and depth <= max_depth:
        results_by_depth[depth] = []
        next_domains = set()

        for domain in current_domains:
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
    show_result(results_by_depth)


if __name__ == "__main__":
    main()

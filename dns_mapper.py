import argparse
import dns.resolver
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

def parse_txt_records(txt_records) : 
    new_domains = []
    new_IPs = []

    for txt_record in txt_records :
        new_domains.extend(extract_new_domain(txt_record))
        new_IPs.extend(extract_new_ip(txt_record))

        
    return new_domains, new_IPs

def extract_new_domain(txt_record) :
    return re.findall(
        rf"(?:[a-z0-9_]" + 
        rf"(?:[a-z0-9-_]{{0,61}}" + 
        rf"[a-z0-9_])?\.)" + 
        r"+[a-z0-9][a-z0-9-_]{0,61}" + 
        rf"[a-z]\.?",
        txt_record,
        flags=re.IGNORECASE,
    )

def extract_new_ip(txt_record) :
    return re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        txt_record,
        flags=re.IGNORECASE,)


def show_result(result):
    for res in result:
        print(f"{res} records : {result[res]}")

def main():
    new_domains = set()
    new_IPs = set()

    args = parse_args()
    result = resolve_records(args.domainName)

    new_domains_temp, new_IPs_temp = parse_txt_records(result['TXT'])

    new_domains.update(new_domains_temp)
    new_IPs.update(new_IPs_temp)

    show_result(result)

    print("\nDomains found:", new_domains)
    print("IPs found:", new_IPs)


if __name__ == "__main__":
    main()

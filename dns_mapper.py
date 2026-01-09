import argparse
import dns.resolver
import re


def parserArg():
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
    new_IPs_address = []
    for txt_record in txt_records :
        # DOMAIN
        new_domain = extract_new_domain(txt_record)
        if new_domain :
            for i in new_domain : 
                new_domains.append(i)

        # IP ADDRESS
        new_IP_address = extract_new_ip(txt_record)
        if new_IP_address :
            for i in new_IP_address :
                new_IPs_address.append(i)
        
    return new_domains, new_IPs_address

def extract_new_domain(txt_record):
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
    new_domains = []
    new_IPs_address = []
    args = parserArg()
    result = resolve_records(args.domainName)
    new_domains_temp, new_IPs_address_temp = parse_txt_records(result['TXT'])
    for i in new_domains_temp : 
        new_domains.append(i)
    for i in new_IPs_address_temp : 
        new_IPs_address.append(i)

    show_result(result)
    print(f"\n Domain à réutilisé : \n {new_domains}")
    print(f"\n IPs à réutilisé : \n {new_IPs_address}")


if __name__ == "__main__":
    main()

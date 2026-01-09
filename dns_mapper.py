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
    for txt_record in txt_records :
        if not txt_record.startswith('"v=spf1'):
            continue

        new_domain = find_new_domain(txt_record)
        if new_domain :
            for i in new_domain : 
                new_domains.append(i)
    return new_domains

def find_new_domain(txt_record):
    return re.findall(
        rf"(?:[a-z0-9_]" + 
        rf"(?:[a-z0-9-_]{{0,61}}" + 
        rf"[a-z0-9_])?\.)" + 
        r"+[a-z0-9][a-z0-9-_]{0,61}" + 
        rf"[a-z]\.?",
        txt_record,
        flags=re.IGNORECASE,
    )


def show_result(result):
    for res in result:
        print(f"{res} records : {result[res]}")

def main():
    new_domains = []
    args = parserArg()
    result = resolve_records(args.domainName)
    new_domains_temp = parse_txt_records(result['TXT'])
    for i in new_domains_temp : 
        new_domains.append(i)
    show_result(result)
    print(f"\n Domain à réutilisé : \n {new_domains}")


if __name__ == "__main__":
    main()

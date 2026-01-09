import argparse
import dns.resolver

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

def show_result(result):
    for res in result:
        print(f"{res} records : {result[res]}")

def main():
    args = parserArg()
    result = resolve_records(args.domainName)
    show_result(result)


if __name__ == "__main__":
    main()

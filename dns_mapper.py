import argparse
import dns.resolver

def parserArg():
    parser = argparse.ArgumentParser()
    parser.add_argument("domainName")
    args = parser.parse_args()
    return args

def resolve_ip(domain):
    result = {}

    try:
        A_records = dns.resolver.resolve(domain, 'A')
        result['A'] = [rdata.to_text() for rdata in A_records]
    except:
        result['A'] = ["No A record found"]

    try:
        AAAA_records = dns.resolver.resolve(domain, 'AAAA')
        result['AAAA'] = [rdata.to_text() for rdata in AAAA_records]
    except:
        result['AAAA'] = ["No AAAA record found"]

    return result

def show_result(result):
    for res in result:
        print(f"{res} records : {result[res]}")

def main():
    args = parserArg()
    result = resolve_ip(args.domainName)
    show_result(result)

if __name__ == "__main__":
    main()

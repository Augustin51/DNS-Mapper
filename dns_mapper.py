import argparse

def parserArg() :
    parser = argparse.ArgumentParser()
    parser.add_argument("domainName")
    args = parser.parse_args()
    return args

def main() :
    args = parserArg()
    return args.domainName

if __name__ == "__main__" :
    print(main())
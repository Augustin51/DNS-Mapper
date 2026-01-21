import pytest
from dns_mapper import ( strip_trailing_dot, extract_domains, extract_ips, crawl_to_tld, subdomain_strategy )


# strip_trailing_dot
def test_strip_trailing_dot_with_dot():
    assert strip_trailing_dot("example.com.") == "example.com"

def test_strip_trailing_dot_without_dot():
    assert strip_trailing_dot("example.com") == "example.com"


# extract_domains
def test_extract_domains_simple():
    text = "Connect to api.example.com and mail.example.com."
    domains = extract_domains(text)
    assert "api.example.com" in domains
    assert "mail.example.com" in domains


# extract_ips
def test_extract_ips_simple():
    text = "Server at 192.168.1.1 is down."
    ips = extract_ips(text)
    assert "192.168.1.1" in ips

def test_extract_ips_ignore_text():
    text = "No IP here!"
    ips = extract_ips(text)
    assert ips == set()


# crawl_to_tld
def test_crawl_to_tld_simple():
    result = crawl_to_tld("sub.example.com")
    assert "example.com" in result
    assert "com" not in result

def test_crawl_to_tld_compound():
    result = crawl_to_tld("sub.example.co.uk")
    assert "example.co.uk" in result
    assert "co.uk" not in result


# subdomain_strategy
def test_subdomain_strategy_basic():
    subs = subdomain_strategy("example.com")
    for sub in ["www.example.com", "mail.example.com", "api.example.com"]:
        assert sub in subs


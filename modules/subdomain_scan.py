import dns.resolver
import random
import string
import requests

def scan_subdomains(domain):

    print(f"Starting subdomain scan on {domain}...")

    wordlist = [
        "www","mail","ftp","api","blog","admin",
        "vpn","portal","dashboard","dev","test",
        "beta","support","shop","m","mobile"
    ]

    found = set()

    random_sub = ''.join(random.choice(string.ascii_lowercase) for _ in range(15))
    test_domain = f"{random_sub}.{domain}"

    wildcard_ips = []

    try:
        answers = dns.resolver.resolve(test_domain, "A")
        wildcard_ips = [r.address for r in answers]
    except:
        pass

    for sub in wordlist:

        subdomain = f"{sub}.{domain}"

        try:
            answers = dns.resolver.resolve(subdomain, "A")
            ips = [r.address for r in answers]

            # ignore wildcard results
            if ips == wildcard_ips:
                continue

            if subdomain not in found:
                print(f"Found: {subdomain}")
                found.add(subdomain)

        except:
            pass

    print("Subdomain scan finished.")

    return list(found)
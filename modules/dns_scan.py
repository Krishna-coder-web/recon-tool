import dns.resolver

def scan_dns(domain):

    records = []

    try:
        answers = dns.resolver.resolve(domain, 'A')

        for r in answers:
            records.append(str(r))

    except:
        pass

    return records
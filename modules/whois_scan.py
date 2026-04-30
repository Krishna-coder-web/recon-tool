import whois


def scan_whois(domain):

    print(f"Starting WHOIS scan on {domain}...")

    try:

        data = whois.whois(domain)

        results = {
            "domain_name": data.domain_name,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers
        }

        print("WHOIS scan finished.")

        return results

    except Exception as e:

        print("WHOIS lookup failed")

        return {}
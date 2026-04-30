import requests


def scan_headers(domain):
    print(f"Scanning headers for {domain}...")

    try:
        url = f"https://{domain}"

        headers_custom = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close"
        }

        response = requests.get(
            url,
            headers=headers_custom,
            timeout=8,
            allow_redirects=True
        )

        final_url = response.url

        # Normalize headers
        raw_headers = {k.lower(): v for k, v in response.headers.items()}

        # Security headers + risk levels
        security_headers = {
            "content-security-policy": "HIGH",
            "strict-transport-security": "HIGH",
            "x-frame-options": "MEDIUM",
            "x-xss-protection": "LOW",
            "x-content-type-options": "MEDIUM",
            "referrer-policy": "LOW",
            "permissions-policy": "MEDIUM"
        }

        analyzed_headers = {}

        for header, risk in security_headers.items():
            if header in raw_headers:
                analyzed_headers[header] = {
                    "status": "Present",
                    "risk": None
                }
            else:
                analyzed_headers[header] = {
                    "status": "Missing",
                    "risk": risk
                }

        return {
            "final_url": final_url,
            "headers": analyzed_headers
        }

    except requests.exceptions.RequestException as e:
        print(f"Header scan failed: {e}")
        return {
            "final_url": None,
            "headers": {}
        }
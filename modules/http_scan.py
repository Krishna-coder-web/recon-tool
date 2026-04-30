import requests


def scan_http(domain):

    print(f"Starting HTTP technology scan on {domain}...")

    technologies = []

    try:

        url = f"https://{domain}"

        response = requests.get(url, timeout=5)

        headers = response.headers
        content = response.text.lower()

        # SERVER HEADER
        if "Server" in headers:
            technologies.append(headers["Server"])

        # TECHNOLOGY DETECTION
        if "wordpress" in content:
            technologies.append("WordPress")

        if "wp-content" in content:
            technologies.append("WordPress")

        if "php" in headers.get("X-Powered-By", "").lower():
            technologies.append("PHP")

        if "nginx" in headers.get("Server", "").lower():
            technologies.append("Nginx")

        if "apache" in headers.get("Server", "").lower():
            technologies.append("Apache")

        print("HTTP technology scan finished.")

        return list(set(technologies))

    except Exception:

        print("HTTP scan failed")

        return []
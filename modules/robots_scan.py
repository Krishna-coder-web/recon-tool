import requests


def scan_robots(domain):

    print(f"Starting robots.txt scan on {domain}...")

    results = {
        "found": False,
        "entries": []
    }

    for protocol in ["https://", "http://"]:

        url = f"{protocol}{domain}/robots.txt"

        try:

            r = requests.get(url, timeout=5)

            if r.status_code == 200:

                print(f"robots.txt found at {url}")

                results["found"] = True

                lines = r.text.splitlines()

                for line in lines:

                    line = line.strip()

                    if line.startswith("Disallow") or line.startswith("Allow"):
                        print(f"Found: {line}")
                        results["entries"].append(line)

                break

        except Exception:
            continue

    if not results["found"]:
        print("robots.txt not found")

    return results
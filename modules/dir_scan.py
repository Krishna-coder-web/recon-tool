import requests
import os
import random
import string


def scan_directories(domain):

    print(f"Starting directory scan on {domain}...")

    wordlist_path = os.path.join(
        os.path.dirname(__file__),
        "wordlists",
        "directories.txt"
    )

    found_dirs = []

    try:

        random_path = ''.join(random.choice(string.ascii_lowercase) for i in range(15))
        fake_url = f"http://{domain}/{random_path}"

        baseline_response = requests.get(fake_url, timeout=5)
        baseline_length = len(baseline_response.text)

        print(f"Baseline response length: {baseline_length}")

        with open(wordlist_path, "r") as file:
            directories = file.read().splitlines()

        for d in directories:

            url = f"http://{domain}/{d}"

            try:

                r = requests.get(url, timeout=5)

                if r.status_code == 404:
                    continue

                response_length = len(r.text)

                if abs(response_length - baseline_length) > 50:

                    print(f"Found directory: {url}")
                    found_dirs.append(url)

            except:
                pass

        print("Directory scan finished.")

        return found_dirs

    except Exception as e:
        print("Directory scan failed:", e)
        return []
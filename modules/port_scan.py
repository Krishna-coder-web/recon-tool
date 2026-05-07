import nmap

def scan_ports(target):

    print(f"Starting port scan on {target}...")

    scanner = nmap.PortScanner()

    scanner.scan(target, '1-65535', arguments='-T4')

    open_ports = []

    hosts = scanner.all_hosts()

    if len(hosts) == 0:
        print("No hosts found.")
        return []

    host = hosts[0]

    for proto in scanner[host].all_protocols():

        ports = scanner[host][proto].keys()

        for port in ports:
            open_ports.append(port)

    print("Port scan finished.")

    return open_ports
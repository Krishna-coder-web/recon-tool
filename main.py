from core.recon_controller import run_scan

history = {}

def start_cli():
    print("Recon Framework Started")
    print("Type 'help' to see commands")

    while True:

        command = input(">> ").strip()

        if command == "exit":
            print("Exiting framework")
            break

        elif command == "help":
            print("\nAvailable Commands")
            print("scan <domain>  - run reconnaissance scan")
            print("history        - show scanned targets")
            print("show <domain>  - display stored results")
            print("exit           - close program\n")

        elif command.startswith("scan "):

            target = command.split(" ")[1]

            results = run_scan(target)

            history[target] = results

        elif command == "history":

            if history:
                print("\nScanned Targets:")
                for h in history:
                    print(h)
            else:
                print("No scans performed yet.")

        elif command.startswith("show "):

            target = command.split(" ")[1]

            if target in history:

                data = history[target]

                print("\nPORTS:")
                print(data["ports"])

                print("\nDNS:")
                print(data["dns"])

                print("\nSUBDOMAINS:")
                print(data["subdomains"])

            else:
                print("Target not found in history.")

        else:
            print("Unknown command. Type 'help'.")
            
if __name__ == "__main__":
    start_cli()
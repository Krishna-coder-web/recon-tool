def parse_command(command):
    parts = command.split()

    if parts[0] == "scan":
        return {
            "action": "scan",
            "target": parts[1]
        }

    if parts[0] =="dns":
        return{
            "action": "dns",
            "target": parts[1] 
        }

    return {"action": "unknown"}
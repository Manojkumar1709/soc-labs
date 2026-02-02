import re

class LogParser:
    def __init__(self):
        # Regex patterns to extract data from your specific log format
        self.patterns = {
            # Pattern for: "Failed password for invalid user hacker from 192.168.1.104"
            "ssh_fail": r"Failed password for (?:invalid user )?(\w+) from ([\d\.]+)",
            
            # Pattern for: "Accepted publickey for manoj from 192.168.1.104"
            "ssh_success": r"Accepted (?:publickey|password) for (\w+) from ([\d\.]+)",
            
            # Pattern for: "sudo:    manoj : ... COMMAND=/usr/bin/tail"
            # We look for "sudo:", optional spaces, a user, and the COMMAND part
            "sudo_run": r"sudo:\s+(\w+)\s+:.*COMMAND=(.*)$"
        }

    def parse_line(self, line):
        """
        Takes a raw log line and returns a structured dictionary.
        """
        # 1. Extract Timestamp (The first part of the line)
        # We split by space and take the first item
        parts = line.split(' ')
        timestamp = parts[0]

        # 2. Check for SSH Failed Login
        match = re.search(self.patterns["ssh_fail"], line)
        if match:
            return {
                "timestamp": timestamp,
                "user": match.group(1),
                "source_ip": match.group(2),
                "event_type": "SSH_FAILED_LOGIN",
                "raw": line.strip()
            }

        # 3. Check for SSH Successful Login
        match = re.search(self.patterns["ssh_success"], line)
        if match:
            return {
                "timestamp": timestamp,
                "user": match.group(1),
                "source_ip": match.group(2),
                "event_type": "SSH_SUCCESS_LOGIN",
                "raw": line.strip()
            }

        # 4. Check for Sudo Command
        match = re.search(self.patterns["sudo_run"], line)
        if match:
            return {
                "timestamp": timestamp,
                "user": match.group(1),
                "command": match.group(2).strip(),
                "event_type": "SUDO_COMMAND",
                "raw": line.strip()
            }

        # If no pattern matches, return None
        return None

# --- TEST BLOCK (Runs only when you execute this file directly) ---
if __name__ == "__main__":
    parser = LogParser()
    
    print("--- TESTING PARSER ---")
    
    # Read our sample file
    with open("data/sample_auth.log", "r") as f:
        for line in f:
            parsed_event = parser.parse_line(line)
            if parsed_event:
                print(f"[+] PARSED: {parsed_event}")
            # else:
            #     print(f"[-] SKIPPED: {line[:30]}...")

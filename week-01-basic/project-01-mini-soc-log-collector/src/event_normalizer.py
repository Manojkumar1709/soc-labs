import socket
import json

class EventNormalizer:
    def __init__(self):
        # Automatically get the hostname (e.g., "raspberrypi" or "ubuntu")
        self.hostname = socket.gethostname()

    def normalize(self, parsed_event):
        """
        Takes a parsed dictionary and adds metadata (Host, Standard Keys).
        """
        if not parsed_event:
            return None

        # Create the standard schema (AXIORA TIER-1 STANDARD)
        normalized_event = {
            "timestamp": parsed_event.get("timestamp"),
            "host": self.hostname,  # <-- Added Metadata
            "event_type": parsed_event.get("event_type"),
            "user": parsed_event.get("user", "unknown"),
            "source_ip": parsed_event.get("source_ip", "N/A"),
            "command": parsed_event.get("command", "N/A"),
            "raw_log": parsed_event.get("raw")
        }

        return normalized_event

# --- TEST BLOCK ---
if __name__ == "__main__":
    norm = EventNormalizer()
    
    # Fake parsed data to test
    sample_parsed = {
        "timestamp": "2026-02-02T07:30:00",
        "user": "hacker",
        "source_ip": "192.168.1.50",
        "event_type": "SSH_FAILED_LOGIN",
        "raw": "Failed password..."
    }
    
    print("--- TESTING NORMALIZER ---")
    print(json.dumps(norm.normalize(sample_parsed), indent=4))

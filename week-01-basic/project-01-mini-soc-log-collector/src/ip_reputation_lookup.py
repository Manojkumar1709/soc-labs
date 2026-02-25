"""
Simulates an external Threat Intelligence API like AbuseIPDB or VirusTotal.
"""

class IPReputationLookup:
    def __init__(self):
        # Simulated Threat Intel Database
        # Our test attacker was 192.168.1.200, let's pretend that is a known bad IP from Russia.
        self.mock_db = {
            "192.168.1.200": {
                "abuse_confidence_score": 85,
                "total_reports": 24,
                "country_code": "RU",
                "isp": "BadHost Networks",
                "is_malicious": True
            },
            "8.8.8.8": {
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "country_code": "US",
                "isp": "Google LLC",
                "is_malicious": False
            }
        }

    def lookup(self, ip_address):
        """Queries the DB for an IP. Returns benign default if not found."""
        print(f"      [🔍] Querying Threat Intel for IP: {ip_address}...")
        
        # Return known bad data, or default safe data
        return self.mock_db.get(ip_address, {
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "country_code": "Unknown",
            "isp": "Unknown",
            "is_malicious": False
        })

# --- TEST BLOCK ---
if __name__ == "__main__":
    ti = IPReputationLookup()
    print(ti.lookup("192.168.1.200"))
    print(ti.lookup("1.2.3.4")) # Should return default safe

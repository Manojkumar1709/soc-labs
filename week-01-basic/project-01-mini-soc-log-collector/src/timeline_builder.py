import json

class TimelineBuilder:
    def build_timeline(self, attack_data):
        """
        Takes a single attack record (from AttackAnalyzer) and builds a chronological timeline.
        """
        timeline = []
        
        # We look at the 'related_alerts' in the attack group
        alerts = attack_data.get("related_alerts", [])
        
        # Sort them by time just to be sure
        alerts.sort(key=lambda x: x.get("detection_time", ""))

        for alert in alerts:
            timestamp = alert.get("detection_time", "N/A")
            severity = alert.get("severity", "INFO")
            user = alert.get("user", "unknown")
            rule = alert.get("rule", "Unknown Event")
            
            # Create a simple, human-readable event entry
            event_entry = {
                "time": timestamp,
                "event": rule,
                "user_targeted": user,
                "severity": severity,
                "details": alert.get("description", "")
            }
            timeline.append(event_entry)
            
        return timeline

# --- TEST BLOCK ---
if __name__ == "__main__":
    # We need to simulate the input coming from Attack Analyzer
    # Let's load the data from the analyzer's output if we can, 
    # OR just paste the sample you just generated for testing.
    
    # For now, let's try to import the analyzer and run it to get real data
    from attack_analyzer import AttackAnalyzer
    
    analyzer = AttackAnalyzer()
    attacks = analyzer.analyze_attacks()
    
    if attacks:
        builder = TimelineBuilder()
        print(f"--- ATTACK TIMELINE ({len(attacks)} attacks detected) ---")
        
        for attack in attacks:
            print(f"\n[+] Timeline for Attacker: {attack['source_ip']}")
            timeline = builder.build_timeline(attack)
            print(json.dumps(timeline, indent=4))
    else:
        print("[-] No attacks found to build timeline.")
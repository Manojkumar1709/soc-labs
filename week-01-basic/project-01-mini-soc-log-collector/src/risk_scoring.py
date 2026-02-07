class RiskScorer:
    def calculate_risk(self, attack_record):
        """
        Calculates a Risk Score (0-100) based on attack behavior.
        """
        risk_score = 0
        severity_label = "LOW"
        
        # FACTOR 1: Volume of Attempts (+10 per attempt, max 50)
        attempts = attack_record.get("attempt_count", 0)
        risk_score += min(attempts * 10, 50)
        
        # FACTOR 2: High-Value Targets (+20)
        # Did they try to log in as root, admin, or db_admin?
        targets = attack_record.get("target_users", [])
        high_value_users = {"root", "admin", "administrator", "db_admin"}
        
        # Check if any target is in the high_value list
        if any(u in high_value_users for u in targets):
            risk_score += 20
            
        # FACTOR 3: The "Breach" Indicator (+40)
        # Did they succeed after failing? (Check for "SSH Successful Login" in related alerts)
        related_alerts = attack_record.get("related_alerts", [])
        has_success = False
        for alert in related_alerts:
            if alert.get("rule") == "SSH Successful Login":
                has_success = True
                break
        
        if has_success:
            risk_score += 40  # HUGE penalty for success
            
        # Cap the score at 100
        risk_score = min(risk_score, 100)
        
        # Assign Label
        if risk_score >= 80:
            severity_label = "CRITICAL"
        elif risk_score >= 50:
            severity_label = "HIGH"
        elif risk_score >= 20:
            severity_label = "MEDIUM"
            
        return {
            "risk_score": risk_score,
            "severity_label": severity_label,
            "breakdown": {
                "attempts_score": min(attempts * 10, 50),
                "high_value_target": any(u in high_value_users for u in targets),
                "successful_breach": has_success
            }
        }

# --- TEST BLOCK ---
if __name__ == "__main__":
    from attack_analyzer import AttackAnalyzer
    
    # 1. Get the Attack Data
    analyzer = AttackAnalyzer()
    attacks = analyzer.analyze_attacks()
    
    # 2. Score the first attack found
    if attacks:
        scorer = RiskScorer()
        attack = attacks[0] # Test with the first one (192.168.1.200)
        
        risk = scorer.calculate_risk(attack)
        
        print(f"--- RISK ASSESSMENT FOR {attack['source_ip']} ---")
        print(f"Risk Score: {risk['risk_score']}/100")
        print(f"Severity:   {risk['severity_label']}")
        print(f"Breakdown:  {risk['breakdown']}")
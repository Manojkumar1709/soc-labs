"""
Dynamically adjusts the incident risk score based on Threat Intelligence.
"""

class RiskAdjuster:
    def adjust_risk(self, base_score, ti_data):
        abuse_score = ti_data.get("abuse_confidence_score", 0)
        modifier = 0

        # Apply Risk Modifiers based on Abuse Score
        if abuse_score > 80:
            modifier = 30
        elif abuse_score >= 50:
            modifier = 20
        elif abuse_score == 0:
            # If the IP has literally zero bad reports, we can slightly lower the risk
            modifier = -10 

        # Calculate final score and clamp it between 0 and 100
        final_score = base_score + modifier
        final_score = max(0, min(final_score, 100))

        # Re-calculate Severity (Tier-3 Escalation Matrix)
        severity = "LOW"
        if final_score >= 90:
            severity = "CRITICAL"
        elif final_score >= 70:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MEDIUM"

        return {
            "original_score": base_score,
            "ti_modifier": modifier,
            "final_score": final_score,
            "final_severity": severity
        }

# --- TEST BLOCK ---
if __name__ == "__main__":
    adjuster = RiskAdjuster()
    mock_ti = {"abuse_confidence_score": 85}
    print(adjuster.adjust_risk(70, mock_ti)) # Should jump to 100 CRITICAL

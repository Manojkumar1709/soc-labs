import json
import os
import glob
from mitre_database import MITRE_ATTACK_DB

class MitreMapper:
    def __init__(self, investigations_dir="investigations"):
        self.investigations_dir = investigations_dir

    def enrich_report(self, filepath):
        """Reads a base report, applies MITRE logic, and returns the enriched data."""
        try:
            with open(filepath, 'r') as f:
                report = json.load(f)
        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")
            return None

        # Initialize MITRE block
        mitre_attack = {
            "techniques": [],
            "confidence": "LOW"
        }
        
        # --- STEP 3: Multi-Technique Logic Extraction ---
        # We look at the risk breakdown to understand what happened
        risk_breakdown = report.get("risk_assessment", {}).get("breakdown", {})
        attempts_score = risk_breakdown.get("attempts_score", 0)
        successful_breach = risk_breakdown.get("successful_breach", False)
        
        # Rule 1: T1110 - Brute Force
        if attempts_score > 0:
            mitre_attack["techniques"].append(MITRE_ATTACK_DB["SSH_BRUTE_FORCE"])
            mitre_attack["confidence"] = "MEDIUM" # Baseline confidence for just trying

        # Rule 2 & 3: T1078 (Valid Accounts) & T1021 (Remote Services)
        if successful_breach:
            mitre_attack["techniques"].append(MITRE_ATTACK_DB["SSH_SUCCESS_AFTER_FAILURE"])
            mitre_attack["techniques"].append(MITRE_ATTACK_DB["SSH_REMOTE_ACCESS"])
            
            # --- STEP 4: Confidence Scoring ---
            # If they actually got in after brute forcing, our confidence is HIGH
            mitre_attack["confidence"] = "HIGH" 

        # Append the new data to the report
        report["mitre_attack"] = mitre_attack
        return report

    def run_all(self):
        """Finds all investigation reports and creates new MITRE-enriched versions."""
        print("--- STARTING MITRE ATT&CK ENRICHMENT ---")
        
        # Find all JSON files in investigations/ that don't already have 'mitre' in the name
        files = glob.glob(f"{self.investigations_dir}/investigation_*.json")
        base_files = [f for f in files if "mitre" not in f]
        
        if not base_files:
            print("[-] No base investigation reports found. Run Week 1 Project 2 first.")
            return

        for filepath in base_files:
            print(f"[*] Processing {filepath}...")
            enriched_report = self.enrich_report(filepath)
            
            if enriched_report:
                # --- STEP 5: Save Enriched Report ---
                new_filepath = filepath.replace(".json", "_mitre.json")
                with open(new_filepath, 'w') as f:
                    json.dump(enriched_report, f, indent=4)
                
                print(f"[+] Saved enriched report to {new_filepath}")
                tech_count = len(enriched_report['mitre_attack']['techniques'])
                conf = enriched_report['mitre_attack']['confidence']
                print(f"    -> Mapped {tech_count} techniques with {conf} confidence.\n")

# --- TEST BLOCK ---
if __name__ == "__main__":
    mapper = MitreMapper()
    mapper.run_all()
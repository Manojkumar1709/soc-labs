import time
import sys
from log_parser import LogParser
from event_normalizer import EventNormalizer
from detection_engine import DetectionEngine
from alert_engine import AlertEngine

def main():
    print("--- AXIORA MINI SOC: INITIALIZING ---")
    
    # 1. Initialize all components
    parser = LogParser()
    normalizer = EventNormalizer()
    detector = DetectionEngine()
    alerter = AlertEngine()

    log_file_path = "data/sample_auth.log"
    print(f"[*] Monitoring Log File: {log_file_path}")
    print("[*] Waiting for logs...")
    print("-" * 50)

    # 2. Read the log file line by line
    try:
        with open(log_file_path, "r") as f:
            lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # --- PIPELINE START ---
                
                # A. Parse
                parsed_event = parser.parse_line(line)
                if not parsed_event:
                    continue # Skip uninteresting lines

                # B. Normalize
                normalized_event = normalizer.normalize(parsed_event)

                # C. Detect
                alerts = detector.detect(normalized_event)

                # D. Alert
                if alerts:
                    alerter.process_alerts(alerts)
                
                # --- PIPELINE END ---
                
                # Small delay to simulate real-time processing
                time.sleep(0.5) 

    except FileNotFoundError:
        print(f"[!] Error: File {log_file_path} not found. Run Step 2 first!")

    print("\n--- PROCESSING COMPLETE ---")
    print("[*] Alerts saved to alerts/alerts.json")

if __name__ == "__main__":
    main()

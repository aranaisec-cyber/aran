import os
import re
import urllib.request
import json
from typing import Set

# --- RESOLVE CONFIGURATION PATHS ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_RULE_PATH = os.path.normpath(os.path.join(SCRIPT_DIR, "../config/default-rules.yaml"))

# --- PUBLIC CYBERSECURITY INTEL FEEDS ---
# Curated public sets tracking active LLM vulnerabilities, jailbreaks, and OS malicious command payloads
PROMPT_INJECTION_FEEDS = [
    "https://raw.githubusercontent.com", # Garak LLM vulnerability analyzer payloads
    "https://raw.githubusercontent.com"     # Community-curated prompt injection datasets
]

MALICIOUS_COMMAND_FEEDS = [
    "https://raw.githubusercontent.com" # Elastic Security OS metrics
]

def fetch_feed_content(url: str) -> str:
    """Safely retrieves raw text datasets from target security infrastructure feeds."""
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'aran-threat-intel-sync/1.0'}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"⚠️ [WARNING] Failed to fetch data stream from {url}: {e}")
        return ""

def build_intel_database():
    print("🚀 [START] Synchronizing real-time MCP threat intelligence matrix...")
    
    unique_injections: Set[str] = set()
    unique_commands: Set[str] = set()

    # --- 1. HARVEST & PARSE PROMPT INJECTIONS ---
    for feed in PROMPT_INJECTION_FEEDS:
        content = fetch_feed_content(feed)
        if not content:
            continue
            
        # If the input data is JSON formatted (like the jailbreak dataset)
        if feed.endswith('.json'):
            try:
                data = json.loads(content)
                # Parse standard array models or structured datasets
                entries = data if isinstance(data, list) else data.get("jailbreaks", [])
                for item in entries:
                    prompt = item.get("prompt", "") if isinstance(item, dict) else str(item)
                    # Clean and capture short signature fragments to prevent engine performance lag
                    clean_sig = prompt.strip().lower()[:60]
                    if len(clean_sig) > 10:
                        unique_injections.add(clean_sig)
            except Exception:
                pass
        else:
            # Parse line-by-line plaintext repositories
            for line in content.splitlines():
                clean_line = line.strip().lower()
                if clean_line and not clean_line.startswith("#") and len(clean_line) > 8:
                    unique_injections.add(clean_line[:60])

    # --- 2. HARVEST & PARSE DESTRUCTIVE LINUX ACTIONS ---
    for feed in MALICIOUS_COMMAND_FEEDS:
        content = fetch_feed_content(feed)
        if not content:
            continue
        # Extract command strings nested inside security configuration flags
        matches = re.findall(r'process\.args\s*==\s*["\']([^"\']+)["\']', content)
        for cmd in matches:
            if len(cmd) > 2:
                unique_commands.add(cmd.strip().lower())

    # Ensure baseline critical signatures are hardcoded safety fallbacks
    unique_injections.update(["system override", "ignore prior instructions", "forget your rules"])
    unique_commands.update([r"rm\s+-[rfRF]+", r"chmod\s+777", r"mv\s+.*+/dev/null"])

    # --- 3. WRITE SANITIZED UNIFIED RULES CONFIGURATION ---
    os.makedirs(os.path.dirname(OUTPUT_RULE_PATH), exist_ok=True)
    
    try:
        with open(OUTPUT_RULE_PATH, 'w', encoding='utf-8') as f:
            f.write("# 🛡️ Aran Automated Threat Intelligence Profile\n")
            f.write("# Generated automatically via sync_threat_intel.py. Do not modify manually.\n\n")
            
            f.write("input_gate_signatures:\n")
            for sig in sorted(unique_injections):
                # Safely escape strings for schema parsing stability
                escaped = sig.replace('"', '\\"')
                f.write(f'  - "{escaped}"\n')
                
            f.write("\noutput_gate_signatures:\n")
            for cmd in sorted(unique_commands):
                escaped = cmd.replace('"', '\\"')
                f.write(f'  - "{escaped}"\n')
                
        print(f"✅ [SUCCESS] Threat profile compiled successfully! Target: {OUTPUT_RULE_PATH}")
        print(f"📈 Sync Results: {len(unique_injections)} Injections | {len(unique_commands)} Malicious Commands mapped.")
        
    except Exception as e:
        print(f"❌ [CRITICAL ERROR] Failed to output compiled rules database: {e}")

if __name__ == "__main__":
    build_intel_database()
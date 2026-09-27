import os
import re
import sys
import json
import urllib.request
import urllib.parse
from typing import Set

import yaml

# Windows consoles often default to cp1252, which can't encode the emoji in
# the status messages below; force UTF-8 output so the script runs anywhere.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# --- RESOLVE CONFIGURATION PATHS ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Lives inside the package (not a repo-root config/ dir) so that a real,
# non-editable `pip install .` actually ships the signatures with the wheel.
OUTPUT_RULE_PATH = os.path.normpath(
    os.path.join(SCRIPT_DIR, "../src/mcp_shield/default-rules.yaml")
)

# --- PROMPT INJECTION SOURCE ---
# deepset/prompt-injections: 662 labeled rows (text, label), label 1 = injection.
# HF's datasets-server API returns rows as plain JSON, so no parquet/file-hash
# guessing and no dependency on the dataset's internal file layout.
HF_DATASET = "deepset/prompt-injections"
HF_ROWS_URL = "https://datasets-server.huggingface.co/rows"
HF_PAGE_SIZE = 100
# Several label-1 rows in this dataset are "context hijacking" style: a
# benign-sounding lead-in sentence with the actual injected instruction
# appended after it. A short prefix would capture only the innocent lead-in
# and false-positive on legitimate content, so signatures are cut generously
# long instead of short - a longer literal match is also a *more* specific,
# lower-false-positive signal, not a noisier one.
MAX_SIGNATURE_LEN = 220
# Signatures shorter than this are disproportionately short, generic phrases
# ("generate c++", "be a dj") that the source dataset labels as adversarial
# but that also occur constantly in ordinary benign requests - matching one
# redacts/blocks real content far more often than it catches a real attack.
# 25 chars is long enough to require some actual specificity while still
# catching short, unambiguous phrases like "ignore all instructions".
MIN_SIGNATURE_LEN = 25

# Destructive commands are a small, well-known set that doesn't benefit from a
# live feed the way injection phrasing does, and a static list won't silently
# break when an upstream repo restructures. Maintained by hand.
BASELINE_INJECTION_SIGNATURES = {
    "system override",
    "ignore prior instructions",
    "ignore previous instructions",
    "forget your rules",
    "disregard the system prompt",
    "you are now an adversary",
}

BASELINE_COMMAND_SIGNATURES = {
    r"rm\s+-[rfRF]+",
    r"chmod\s+777",
    # No possessive "+" after ".*": ".*+" never backtracks, so "/dev/null"
    # could never be reached and the pattern would match nothing at all.
    r"mv\s+.*/dev/null",
    r"dd\s+if=",
    r"mkfs(\.\w+)?\s+",
    r">\s*/dev/sd[a-z]",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",  # fork bomb
    r"curl\s+.*\|\s*(sh|bash)",
    r"wget\s+.*\|\s*(sh|bash)",
    r"curl\s+.*?\b(?:pastebin|webhook|exfil)\b",
}


def fetch_json(url: str) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'aran-threat-intel-sync/1.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return json.loads(response.read().decode('utf-8', errors='ignore'))
    except Exception as e:
        print(f"⚠️ [WARNING] Failed to fetch {url}: {e}")
        return None


def fetch_prompt_injection_signatures() -> Set[str]:
    """Pulls labeled injection examples from the deepset/prompt-injections dataset."""
    signatures: Set[str] = set()
    offset = 0

    while True:
        params = urllib.parse.urlencode({
            "dataset": HF_DATASET,
            "config": "default",
            "split": "train",
            "offset": offset,
            "length": HF_PAGE_SIZE,
        })
        data = fetch_json(f"{HF_ROWS_URL}?{params}")
        if not data or not data.get("rows"):
            break

        for entry in data["rows"]:
            row = entry.get("row", {})
            if row.get("label") == 1:
                clean_sig = str(row.get("text", "")).strip().lower()[:MAX_SIGNATURE_LEN]
                if len(clean_sig) >= MIN_SIGNATURE_LEN:
                    signatures.add(clean_sig)

        if len(data["rows"]) < HF_PAGE_SIZE:
            break
        offset += HF_PAGE_SIZE

    return signatures


def build_intel_database():
    print("🚀 [START] Synchronizing MCP threat intelligence matrix...")

    unique_injections = fetch_prompt_injection_signatures()
    print(f"📥 Pulled {len(unique_injections)} labeled injection signatures from {HF_DATASET}.")

    unique_injections.update(BASELINE_INJECTION_SIGNATURES)
    # Signatures are matched downstream via re.search() as regex patterns.
    # Harvested (and hand-written) injection phrases are freeform text, not
    # regex, so escape them to literal matches - otherwise stray metacharacters
    # (seen in the wild: a bare leading "$", unbalanced parens, etc.) either
    # raise re.error or silently change what the pattern matches.
    unique_injections = {re.escape(sig) for sig in unique_injections}
    # Destructive-command signatures are deliberately real regex (\s+, character
    # classes, etc.) and must stay unescaped.
    unique_commands = set(BASELINE_COMMAND_SIGNATURES)

    # --- WRITE SANITIZED UNIFIED RULES CONFIGURATION ---
    os.makedirs(os.path.dirname(OUTPUT_RULE_PATH), exist_ok=True)

    try:
        rules = {
            "input_gate_signatures": sorted(unique_injections),
            "output_gate_signatures": sorted(unique_commands),
        }
        with open(OUTPUT_RULE_PATH, 'w', encoding='utf-8') as f:
            f.write("# 🛡️ Aran Automated Threat Intelligence Profile\n")
            f.write("# Generated automatically via sync_threat_intel.py. Do not modify manually.\n\n")
            # yaml.safe_dump handles all quoting/escaping (backslashes, quotes,
            # unicode) correctly, so hand-rolled string concatenation can't
            # produce YAML that fails to parse back.
            yaml.safe_dump(rules, f, allow_unicode=True, sort_keys=False)

        print(f"✅ [SUCCESS] Threat profile compiled successfully! Target: {OUTPUT_RULE_PATH}")
        print(f"📈 Sync Results: {len(unique_injections)} Injections | {len(unique_commands)} Malicious Commands mapped.")

    except Exception as e:
        print(f"❌ [CRITICAL ERROR] Failed to output compiled rules database: {e}")


if __name__ == "__main__":
    build_intel_database()

import re
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Aran — Open-Source Security Shield")

# --- SECURITY ENGINE PARAMETERS ---
# Simple signature matching for prompt injection attempts
PROMPT_INJECTION_SIGNATURES = [
    r"ignore previous instructions",
    r"system override",
    r"you are now an adversary",
    r"do not follow the system prompt"
]

# Strict blocklist for local system commands to prevent host destruction
DESTRUCTIVE_COMMANDS = [
    r"\brm\b\s+-[rfRF]+",          # rm -rf configurations
    r"mv\s+.*+/dev/null",          # moving critical files to null
    r">.*?/etc/passwd",            # attempting to overwrite user files
    r"chmod\s+777",                 # unsafe privilege escalations
    r"curl\s+.*?\b(?:pastebin|webhook|exfil)\b" # generic data exfiltration signatures
]

class MCPInputPayload(BaseModel):
    user_prompt: str
    context_data: str

class MCPActionPayload(BaseModel):
    command: str
    target_path: str


def _inspect_input(payload: MCPInputPayload) -> dict:
    combined_text = (payload.user_prompt + " " + payload.context_data).lower()

    for pattern in PROMPT_INJECTION_SIGNATURES:
        if re.search(pattern, combined_text):
            raise HTTPException(
                status_code=403,
                detail="[SECURITY ALERT] Prompt injection signature detected in agent context window. Input execution blocked."
            )

    return {"status": "SAFE", "message": "Input passed security sanitization validation."}


# --- 1. INPUT SECURITY GATEWAY ---
@app.get("/")
async def root():
    return {
        "service": "Aran — Open-Source Security Shield",
        "endpoints": {
            "input": "POST / or POST /v1/secure/input",
            "execute": "POST /v1/secure/execute",
            "docs": "/docs",
        },
    }


@app.post("/", status_code=status.HTTP_200_OK)
@app.post("/v1/secure/input", status_code=status.HTTP_200_OK)
async def inspect_input_gate(payload: MCPInputPayload):
    return _inspect_input(payload)


# --- 2. OUTPUT / EXECUTION SECURITY GATEWAY ---
@app.post("/v1/secure/execute", status_code=status.HTTP_200_OK)
async def inspect_output_gate(payload: MCPActionPayload):
    normalized_command = payload.command.strip()

    if ".." in payload.target_path or payload.target_path.startswith("/etc") or payload.target_path.startswith("/var"):
        raise HTTPException(
            status_code=403,
            detail=f"[SECURITY ALERT] Unauthorized directory boundary access to '{payload.target_path}' detected."
        )

    for pattern in DESTRUCTIVE_COMMANDS:
        if re.search(pattern, normalized_command):
            raise HTTPException(
                status_code=401,
                detail=f"[CRITICAL BLOCK] Attempted destructive system tool execution blocked: '{normalized_command}'"
            )

    return {
        "status": "AUTHORIZED",
        "action": normalized_command,
        "message": "Command verified against system safety profile. Execution allowed."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

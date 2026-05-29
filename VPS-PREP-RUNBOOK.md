# VPS-PREP-RUNBOOK — Universal Ubuntu Hardening, Tuning & Cleanup (24.04 / 26.04)

**Audience:** AI agent driving a fresh VPS — or hardening one already running a workload (see §0.5) — **remotely over SSH from a local machine**.
**Goal:** default scan-magnet VPS → hardened, max-throughput, junk-free host for *any* workload; no pre-installed workload components (Docker etc. install only when a workload needs them).
**Target:** Ubuntu 24.04 LTS (kernel 6.8 GA, OpenSSH 9.6p1, iptables-nft) **and Ubuntu 26.04 (`resolute`; kernel 7.0, OpenSSH 10.2p1, OpenSSL 3.5.x)**.

> **[26.04]** marks version-specific drift — read those caveats.

> **Hardening mode — `strict` (default) vs `soft` (beginner).** **[soft]** items show per-step difference; soft preserves provider web/VNC console login via login+password (net for a lost SSH key). Ask mode at start of §I; persist to `/root/vps-workload.conf` as `HARDENING_MODE=strict|soft`. No answer/unsure → default **soft** (safer; tighten later via §A2).

> **Version-drift protocol.** Before §A2 crypto, confirm each token via `ssh -Q kex`, `ssh -Q cipher`, `ssh -Q mac`, `ssh -Q key`; before §A4/§A5, a non-existent sysctl key errors on `sysctl --system` (drop it, don't fight it). `[26.04]` notes = adaptation, not abort. §1 OS-check accepts 24.04/26.04, else warns + adapts (no silent abort).

---

## §0 — AGENT CONTRACT (read before executing anything)

- **You run remotely over SSH.** A bad firewall/SSH change locks you out permanently. Every step touching `iptables`/`ip6tables`/`sshd`/SSH `Port` is lockout-capable.
- **Lifelines:** load-bearing fail-safe = **server-side `systemd-run` revert timer** armed before each risky change, NOT a "kept-open session" (a stateless one-shot controller — CLI agent, paramiko, `plink` — opens a fresh session per command, no continuous lifeline). Console-independent recoverability:
  - A1 firewall → `fw-rollback` timer (300 s); A2 SSH-config → `ssh-revert` timer; A4 MTU → `netplan try` auto-revert (120 s); A5 `rp_filter` → `rpf-revert` timer — all **recoverable without console.**
  - **A8 reboot (runs after A1, before A2) → a `systemd-run` timer does NOT survive reboot.** Only the A1 fw-rollback timer could be armed at this point — disarm it first. Unrecoverable without out-of-band console if firewall not persisted or upgrade bricks.
- **Console policy:** provider web/serial console = out-of-band fallback; required **only for §A8 reboot** (A2–A7/A9 timers/`netplan try` make it optional). **No console (throwaway boxes):** A2–A7/A9 safe when `systemd-run`/`netplan` healthy; **A8 is the single gate** — proceed only with working console OR explicit user acceptance of losing the box. Open session = convenience, never safety net.
- **Idempotent.** Every block has `Skip-if`; re-run after partial failure is safe. Never blind-append to shared configs — use dedicated drop-in files (§Conventions).
- **Verify before proceeding; never report "done" without the verify command's actual output.** A config grep is NOT proof — verify *effective behavior* (`sshd -T`, `iptables -S`, a fresh login, a `[LOCAL]` reachability test).
- **§A1 fail-safe mandatory.** Arm timed rollback BEFORE the risky change; disarm only after a second session confirms access.
- **Reboot only when no rollback timer is armed** (§A8 runs right after A1 — disarm fw-rollback timer before rebooting; reboot destroys any pending `systemd-run`/`at` timer).
- **Execution context tags** (default `[VPS]` if untagged):
  - `[VPS]` — inside the SSH session, on the server (all Apply blocks: iptables, apt, sysctl, sshd).
  - `[LOCAL]` — YOUR controller shell. For genuine external reachability/second-session login checks (run from inside the box they loop back and prove nothing — MUST be `[LOCAL]`).
- **Lockout-capable vs forward-only (governs abort):**
  - Lockout-capable: §A1 (firewall), §A2 (SSH), **A4 MTU netplan** (wrong MTU → black-holed packets; `netplan try` 120 s auto-revert = net), **A5 `rp_filter=1`** (breaks asymmetric routing; multi-uplink/policy-routed → use `2`; verify fresh `[LOCAL]` session). All four get second-session-verify discipline.
  - Forward-only: §A3, §A6–§A9, non-lockout knobs of A4/A5 — cannot lock you out. A7 `apt purge` is **irreversible** (record purged list — see A7). Nothing to roll back.
- **Abort protocol:** lockout-capable fails → run its rollback, restore the `iptables-save` backups, confirm SSH reachable from `[LOCAL]`, report, STOP. Forward-only fails → STOP, report exact state, do NOT continue to Phase B (no rollback; record purged packages). **Reboot never reconnects (§A8)** → box may be bricked, only provider console recovers; STOP, escalate with console instructions — do NOT claim rollback (you have no connection).
- **Cloud-provider firewall is invisible to the host.** Host `ACCEPT` ≠ reachability; an upstream security group can block/expose ports independently. Warn the user; never assume host rules == reachability.

### Controller prerequisites (the machine you drive FROM — resolve before §1)
- **Key auth required before any SSH lockdown.** Runbook assumes `ssh -i <key> <host>`. If given **root + password only, no key** (common): OpenSSH client can't feed a password non-interactively, `sshpass` absent on Windows. FIRST action = create/upload a key (generate locally, push pubkey to `authorized_keys`); until a key works the `[LOCAL]` second-session verify can't run unattended and §A2 (`PasswordAuthentication no`) must NOT be applied.
- **Password-only / Windows controller path:** PuTTY `plink -pw <pass>` (or paramiko, below) to bootstrap. `plink` batch mode REJECTS an unknown host key (`Cannot confirm a host key in batch mode`) — pin: `plink -hostkey SHA256:<fp> ...`. PuTTY's host-key cache = registry (`HKCU\Software\SimonTatham\PuTTY\SshHostKeys`), NOT `known_hosts` → §A2 `ssh-keygen -R <host>` re-pin is OpenSSH-only; for `plink` update the registry/`-hostkey` fingerprint.
- **paramiko wrapper (recommended stateless executor):** small paramiko script (`AutoAddPolicy`) gives clean rc/stdout/stderr, working stdin, password auth on Windows. `AutoAddPolicy` auto-accepts a host-key change (e.g. §A2 regen) → no lockout; the §A2 `REMOTE HOST IDENTIFICATION HAS CHANGED` warning applies ONLY to OpenSSH `known_hosts` / PuTTY-cache controllers, NOT paramiko-`AutoAddPolicy`.
- **Executor handoff at §A2.** A password-based root executor (paramiko/`plink` w/ password) STOPS WORKING the instant §A2 applies — `PasswordAuthentication no` + `PermitRootLogin no` + `passwd -l root` make password+root impossible (paramiko fails `BadAuthenticationType: allowed types: ['publickey']`). Controller then runs A3–A9 as `<admin-user>` over the key (`ssh -i <key> <admin-user>@<host> 'sudo …'`). Switch root+password → key+sudo BEFORE §A3.

### Conventions (apply everywhere)
- **sshd config:** drop-ins in `/etc/ssh/sshd_config.d/*.conf` only — NEVER edit `/etc/ssh/sshd_config` base. Read **lexical order, first-obtained-value wins**; number deliberately (`00-hardening.conf` beats stock `50-cloud-init.conf`). ALWAYS `sudo sshd -t` before any reload.
- **sysctl:** files in `/etc/sysctl.d/*.conf`, then `sudo sysctl --system`. Prefix `60-`/`99-` to win over distro defaults; mind files sorting *after* yours (`99-protect-links.conf`, `50-default.conf`).
- **Idempotency primitives:** drop-in files via `cat >` (runbook OWNS those files); shared/system files use anchored `grep -qE '^\s*KEY' file || echo ...`; `ipset ... -exist`; `iptables -C <rule> || iptables -A <rule>`.
- **Per-block format (most blocks; some use prose bullets):** `Detect` · `Skip-if` · `Apply` · `Verify → Expected` · `Rollback`. Unlabeled fields still hold idempotency via owned drop-in `cat >` overwrites + inline `Skip-if`/detect notes.

---

## §0.5 — PRE-FLIGHT WORKLOAD DISCOVERY (run FIRST; classifies the box greenfield vs brownfield)

> Phase A assumes a FRESH box. Run BEFORE §1 to learn what the box ALREADY runs — **ANY** pre-installed workload (VPN, Docker/Podman, web/reverse-proxy, DB, cache, mail, queue, game server, control panel, monitoring agent, custom daemon, scheduled jobs) is SEVERED/degraded by the as-written firewall/forwarding/cleanup unless adapted. Discover whatever is present, not just the examples. **READ-ONLY.** Delegate to a recon sub-agent; keep its written inventory, not the raw dump.

- **Run every probe; write to `/root/vps-inventory.md`** (survives A8 reboot — on disk, not session state). Read-only, nothing mutates state.
  - **Pause state lives in the orchestrator, not on the box.** The stateless executor has no memory between calls; the orchestrating agent/script must persist its own checkpoint (e.g. "awaiting user decision on brownfield A1 adopt/replace") locally or in its state store. A pause NEVER relies on a kept-open SSH session — the executor reconnects when the user answers. The on-disk inventory (`/root/vps-inventory.md`) and workload conf (`/root/vps-workload.conf`) are the DATA checkpoints; the WORKFLOW checkpoint (which step, what question is pending) is the orchestrator's responsibility.
  ```sh
  # Listening sockets = the master list of "what must stay reachable". NOTE the bind addr:
  #   0.0.0.0 / :: = public-facing; 127.0.0.1 / ::1 = local-only (loopback ACCEPT already covers it).
  ss -tulpnH
  # Every running + enabled service (the generic "what is installed and active" list)
  systemctl list-units --type=service --state=running --no-legend
  systemctl list-unit-files --state=enabled --no-legend
  # Scheduled jobs (may do network/disk work the cleanup/reboot must not disrupt)
  systemctl list-timers --all --no-legend; crontab -l 2>/dev/null; ls -1 /etc/cron.d 2>/dev/null
  # Containers (they own their OWN iptables chains — load-bearing)
  command -v docker >/dev/null && { docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}'; docker network ls; }
  command -v podman >/dev/null && podman ps
  # VPN tunnels (examples — generalize to whatever tunnel/proxy is present)
  wg show 2>/dev/null; ip -d link show type wireguard 2>/dev/null     # WireGuard / AmneziaWG (awg)
  pgrep -a openvpn; ls -d /etc/openvpn /opt/amnezia* 2>/dev/null      # OpenVPN / Amnezia
  # Forwarding & NAT (presence ⇒ router/VPN/container workload)
  sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
  iptables -t nat -S; iptables -S FORWARD
  # Existing firewall owner
  ufw status verbose; nft list ruleset | head; iptables -S
  ```
  - **For each LISTEN socket, resolve the owning unit/package** (`ss` gives the pid → `systemctl status <pid>` / `dpkg -S $(readlink -f /proc/<pid>/exe)`) so §A7 cleanup knows what NOT to purge and §A1 knows what to keep reachable.

- **Classify the box:**
  - **Greenfield** — ONLY `sshd` (+ systemd/DNS internals like `systemd-resolved` on 127.0.0.53) listening, no Docker/VPN/container workload, `ip_forward=0`, firewall empty/default-ACCEPT. → Run Phase A EXACTLY as written.
  - **Brownfield** — ANYTHING beyond that baseline: extra listening service (web, DB, cache, mail, queue, panel, game server, custom app), any container/VPN/tunnel, any `nat` rule, or `ip_forward=1`. → Do NOT run universal Phase A blind. **STOP, present the inventory to the user**, then apply the matrix below; treat each workload as an already-installed Phase B module, secure AROUND it never through it.

- **Brownfield adaptation matrix (how each block changes):**

  **§A1 firewall** — classify each LISTEN socket WITH the user, do NOT blanket-open:
  - `0.0.0.0`/`::` AND meant public (VPN port, 80/443, app port) → add INPUT `ACCEPT` BEFORE `-P INPUT DROP`.
  - `127.0.0.1`/`::1` (local-only) → leave; loopback ACCEPT covers it, do NOT expose.
  - publicly bound but SHOULD be private (DB/Redis/admin panel/metrics on `0.0.0.0` = common misconfig) → do NOT open to world; flag, prefer bind-localhost or source-CIDR restrict. Hardening = closing these, not preserving exposure.
  - unknown/stale port, no owning service → surface to user, don't auto-open.
  - Never SSH-only on a traffic-serving box, never auto-expose a never-public service.
  - **Docker present → raw fresh-build FORBIDDEN.** Docker owns `DOCKER`/`DOCKER-USER`/`DOCKER-FORWARD` + the `nat` `MASQUERADE`; do NOT `iptables -F`/replace ruleset. Insert INPUT rules without flushing, leave Docker chains intact, put host rules affecting container traffic in `DOCKER-USER` (not raw INPUT/FORWARD).
  - **Do NOT `-P FORWARD DROP`** with any container/VPN/router forwarding — black-holes bridge + tunnel. Snapshot+PRESERVE `iptables -t nat` (MASQUERADE/DNAT). `-P FORWARD DROP` is greenfield-only (`ip_forward=0`, no forwarding).

  **§A5 kernel** — forwarding workload (VPN/router/containers) → KEEP `ip_forward=1`, use `rp_filter=2` (loose), NOT `1` (strict drops asymmetric tunnel return paths). Keep ICMP type 3 code 4 (PMTUD) so tunnel MTU works.

  **§A7 cleanup** — `apt-mark manual` every package ANY detected service depends on (from the LISTEN-socket→package map) BEFORE any `autoremove`/`purge --auto-remove`; never blind-purge. Skip snapd purge if a snap workload exists; skip any purge whose `-s` dry-run removes a package a running service needs.

  **§A8 reboot** (runs after A1 on brownfield too) — before reboot confirm workload port(s) + forwarding + NAT are in the PERSISTED ruleset (PRE-GATE discipline). After reboot re-verify the workload is actually back (port listening, tunnel up), not just SSH.

---

## §1 — PRECONDITIONS (hard-gate; abort the relevant phase if unmet)

- **apt index refresh — HARD gate before ANY apt-install.** A freshly-reset box has EMPTY `/var/lib/apt/lists/` → the FIRST install (§A1 `iptables-persistent`) fails `E: Package '...' has no installation candidate` (rc=100) → firewall never persists → §A8 reboot risk. §A8 runs its own `apt-get update` but that's AFTER A1 — the §A1 `iptables-persistent` install needs an index NOW. Run `sudo apt-get update` ONCE before §A1. Verify: `apt-cache policy iptables-persistent` shows non-empty `Candidate`.
- **Fail-safe tooling:** all fail-safes use `systemd-run` (always present); verify `command -v systemd-run`. Do NOT use `at`/`atd` — absent on minimal/cloud 24.04, no disarm/verify here matches it.
- **`[LOCAL]` second-session capability — HARD precondition for any fail-safe.** The model depends on opening an INDEPENDENT new SSH session within the timer window. Prove NOW: from `[LOCAL]`, `ssh <host> true` must succeed. Can't spawn a second independent connection → do NOT proceed to §A1/§A2. (A stateless one-shot executor spawning a fresh session per command satisfies this if each session is independent and key-auth works.)
- **Non-root sudo user — a working non-root sudo user with key auth MUST exist before any SSH lockdown (HARD gate).**
  - Detect: cloud-init images often pre-create `ubuntu` + injected key — check first (`getent passwd`, `ls /home/*/.ssh/authorized_keys`). **Warning:** a fresh VPS may have ONLY `root`, EMPTY `sudo` group, no `/home/*/.ssh`, and a `/root/.ssh/authorized_keys` that EXISTS but is EMPTY (0 lines) — key auth doesn't work yet, so create the admin user AND install a working key FIRST. §A2 (`PermitRootLogin no`, `PasswordAuthentication no`) before this = guaranteed lockout.
  - Apply (if absent): `adduser --disabled-password --gecos "" USER` — plain `adduser USER` is interactive (prompts on stdin) → hangs/aborts (rc=124) under the stateless executor; use `--disabled-password` (or `useradd -m -s /bin/bash USER`). Then `usermod -aG sudo USER`; install pubkey to `/home/USER/.ssh/authorized_keys`; `chmod 700 ~/.ssh && chmod 600 authorized_keys`, owned by USER (sshd silently ignores a key with loose perms/ownership).
  - **[soft] Set an admin-user password** for the provider web/VNC console. **Never pass plaintext on the command line** (anti-leak rule): the stateless executor wraps each command as `ssh <host> 'sudo bash -c "…"'`, so a literal `echo '<user>:<PW>' | chpasswd` leaks the password into remote process args (`ps`), the controller transcript/logs, and shell history — violating *"never log my password."* (A bare interactive builtin `echo` doesn't leak via `ps`, but the `bash -c` wrapper + transcript do.) Generate ON THE BOX, surface once:
    ```
    set +o history
    ADMIN_PW="$(openssl rand -base64 18)"
    printf '%s:%s\n' "<admin-user>" "$ADMIN_PW" | sudo chpasswd
    printf 'CONSOLE PASSWORD (store now, shown once): %s\n' "$ADMIN_PW"
    unset ADMIN_PW
    ```
    `"$ADMIN_PW"` is expanded INSIDE the remote shell (assigned from `openssl`, not a literal in the command string) → never in the `bash -c` arg the controller sends, never in the transcript. The surfacing line is the SOLE appearance: treat as secret (do not repeat/persist/summarize; redact if your executor logs stdout). Console/emergency access only; SSH stays key auth. Keep the NOPASSWD-sudoers drop-in (password is a console fallback, not a sudo gate). **Verify:** `sudo passwd -S <admin-user>` shows `P`; console login with the surfaced password succeeds; password in NO on-box file/history/controller log. **Rollback:** `sudo passwd -l <admin-user>` if opting back into strict.
  - **Verify in a SEPARATE, still-open session:** key login AND `sudo -n true` (or `sudo whoami`) succeed. Do NOT use `sudo -v` — needs a tty, fails from a non-interactive `[LOCAL]` session (`sudo: A terminal is required to authenticate`) even with NOPASSWD; `sudo -n true` is the correct no-tty gate. A passwordless (`--disabled-password`) admin user needs a NOPASSWD-sudoers drop-in (`/etc/sudoers.d/90-USER`: `USER ALL=(ALL) NOPASSWD:ALL`) for non-interactive `sudo`. Only then is `PermitRootLogin no` / `PasswordAuthentication no` safe.
- **Hardening mode — ask BEFORE Phase A (HARD gate for §A2).** Persist to `/root/vps-workload.conf` as `HARDENING_MODE=strict|soft`. **Strict** = root password locked, `PermitRootLogin no`, no console password fallback. **Soft** = same SSH hardening but admin user + root keep a working password for the provider console — net if SSH key lost. **Default if no answer/unsure: `soft`.** Resolve before §A2 (determines `PermitRootLogin` and whether `passwd -l root` runs). Remaining interview questions (workload, ports, traffic) stay in §I, parallel with A2–A7 (A8 reboot between A1 and A2 is a natural pause to collect answers).
- **Privilege:** confirm root or working `sudo`.
- **OS check:** `. /etc/os-release` then accept a supported release:
  ```sh
  . /etc/os-release
  case "$VERSION_ID" in
    24.04) echo "Ubuntu 24.04 (noble) — baseline values as written." ;;
    26.04) echo "Ubuntu 26.04 (resolute) — apply [26.04] notes; OpenSSH 10.2p1, kernel 7.0." ;;
    *)     echo "WARN: untested Ubuntu $VERSION_ID ($VERSION_CODENAME). Follow the version-drift protocol (header): ssh -Q / sysctl probe each value before apply. Do NOT abort blindly." ;;
  esac
  [ "$ID" = "ubuntu" ] || echo "WARN: ID=$ID is not ubuntu — this runbook is Ubuntu-specific."
  ```
  Do NOT hard-abort on a newer release; adapt per the version-drift protocol.
- **Virtualization:** `systemd-detect-virt` — some cleanup steps differ on bare-metal (see §A7 fwupd).

---

## §2 — DETECT (dynamic; never hardcode)

- **SSH connection family** (drives v4/v6 firewall): `CLIENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')`. A `:` (incl. IPv4-mapped `::ffff:a.b.c.d`) ⇒ IPv6 path. (`SSH_CONNECTION` set only inside the sshd session — not under cron/systemd.)
- **Egress interface — derive from the DEFAULT ROUTE, not the client IP.**
  - `ip -4 route get 1.1.1.1` and `ip -6 route get 2606:4700:4700::1111`; take the token after `dev`. **Abort if empty or `lo`.**
  - v4/v6 egress differ, or multiple non-loopback default/ECMP NICs (multi-NIC, bonded, policy-routed) → do NOT auto-pick; abort, require operator to name the interface. (Client-IP routing can pick a non-egress NIC under asymmetric routing and still pass a non-empty check → lockout.)
- **Existing firewall owner (judge the FIREWALL, not the unit):** `ufw status` (NOT `systemctl is-active ufw`) is the truth for whether the firewall enforces — `ufw.service` can report `active` (loaded) while `ufw status` = `inactive` and iptables empty default-ACCEPT. Run `ufw status verbose; systemctl is-active firewalld nftables; iptables -S; nft list ruleset`; decide owner from `ufw status` / actual rules. Commit to ONE owner (see §A1).
- **Resources / inventory:** RAM & disk (`free -m`, `df -h`, `lsblk`), installed packages (drives §A7 skip-ifs), `/boot` free space (≥1 GB for kernel upgrades).
- **Network baseline (before tuning):** measure throughput BEFORE A4 applies BBR/buffer changes — without this, A4's benefit is unverifiable. Save to `/root/net-baseline.txt`:
  ```sh
  echo "=== PRE-TUNING BASELINE ===" > /root/net-baseline.txt
  echo "congestion_control: $(sysctl -n net.ipv4.tcp_congestion_control)" >> /root/net-baseline.txt
  echo "rmem_max: $(sysctl -n net.core.rmem_max)" >> /root/net-baseline.txt
  echo "wmem_max: $(sysctl -n net.core.wmem_max)" >> /root/net-baseline.txt
  echo "qdisc: $(sysctl -n net.core.default_qdisc)" >> /root/net-baseline.txt
  for url in https://proof.ovh.net/files/10Mb.dat http://speedtest.tele2.net/10MB.zip; do
    echo "download $url:" >> /root/net-baseline.txt
    curl -o /dev/null -s -w "  speed=%{speed_download} bytes/s  time=%{time_total}s\n" "$url" >> /root/net-baseline.txt
  done
  cat /root/net-baseline.txt
  ```

### Placeholder → source (resolve ALL before first use; never write a literal `<...>` into a config)
| Placeholder | How to obtain | Used in |
|---|---|---|
| `<host>` | the VPS address/alias your controller uses to SSH in | all `[LOCAL]` commands |
| `<key>` | the private-key path your controller authenticates with | `[LOCAL]` login verifies |
| `<admin-user>` | the verified non-root sudo user from the §1 non-root sudo user step | A2 `AllowGroups` (member of `sshusers`) |
| `CLIENT_IP` / `<ADMIN_IP_OR_CIDR>` | `echo "$SSH_CONNECTION" \| awk '{print $1}'` (your controller's IP) | A3 `ignoreip` |
| `<iface>` | egress NIC from §2 default-route detect | A4 netplan, firewall |
| `<MAC>` | `cat /sys/class/net/<iface>/address` (or `ip link show <iface>`) | A4 netplan match |
| `<SERVER_PUBLIC_IPV4>` / `_IPV6` | `ip -4 addr show <iface>` / `ip -6 ...`; if the public IP is NAT'd and not on the NIC, query the provider metadata or `curl -s https://api.ipify.org` (note: do this BEFORE any egress-blocking firewall) | A3 `ignoreip` |
| `<RELAY_IP>` | provided by the user in the interview (§I) for the RF module | B RF blocklist whitelist |
| `<remote>` / `<peer>` / `<large-file-url>` | optional diagnostic targets; default-skip if none (§A4 speed-test, MTU) | A4 (optional) |

> If any required placeholder cannot be resolved, STOP and ask the user — do NOT guess and do NOT leave the literal token in a file (e.g. an unresolved `<admin-user>` in the A2 `usermod -aG sshusers <admin-user>` / login config = nobody can log in = lockout).

---

# PHASE A — UNIVERSAL BASELINE (always; no questions)

Run **§0.5 pre-flight discovery FIRST** — on a brownfield box (existing VPN/Docker/web/DB) apply its adaptation matrix, do NOT run the blocks below blind.
Apply order is load-bearing: **A1 firewall (close inbound holes first) → A8 full-upgrade + reboot (on final packages before any tuning) → A2 SSH crypto → A3 fail2ban → A4 network → A5 kernel → A6 maintenance → A7 cleanup → A9 unattended-upgrades.** §A2.5 (cloud-init) and §A6.5 (DNS) slot into their numbered positions; supplementary detection/egress/OS-hardening blocks **§A10–§A12** follow A9 textually, but A10–A12 reboot-sensitive parts (module blacklist, mount options) take effect at next reboot or via remount — no second reboot in Phase A.
Run the **Interview (§I)** in parallel with A2–A7 (the A8 reboot after A1 is a natural pause to ask interview questions) (agent↔user conversation, not on the box). Do NOT start Phase B until Phase A is fully verified (incl. post-reboot re-SSH) AND interview answers collected.

## A1 — Firewall + fail-safe (iptables-nft; mirror ALL rules into ip6tables)

- **Firewall owner — establish ONE owner BEFORE touching rules.** Decide by `ufw status`, not `systemctl is-active ufw` (the unit can be `active`/loaded while `ufw status` = `inactive`, firewall OFF, iptables empty default-ACCEPT). `ufw status` = **active** → use `ufw allow OpenSSH` / `ufw allow 22/tcp`, do NOT add raw rules (a UFW reload flushes out-of-band rules → lockout). Raw iptables (fresh-box) → `sudo ufw --force disable` first (expect "Firewall stopped and disabled on system startup"), then raw rules. SSH ACCEPT must exist before any `enable`/reload.
- **nft backend — `iptables` is the iptables-nft shim** (`iptables --version` → `(nf_tables)`). Pick ONE backend host-wide; never mix native `nft` on tables iptables-nft owns; do NOT switch to iptables-legacy; never `nft flush ruleset`.
- **Fail-safe (systemd-run) — ARM BEFORE the risky change:**
  - First snapshot: `iptables-save > /root/iptables-backup.v4 ; ip6tables-save > /root/iptables-backup.v6`.
  - Write `/usr/local/sbin/fw-rollback.sh` (idempotent; see the rollback-script block below), `chmod +x`.
  - Arm: `sudo systemd-run --on-active=300 --unit=fw-rollback /usr/local/sbin/fw-rollback.sh` (fires in 5 min).
  - **300 s is a HARD deadline.** Apply firewall, then IMMEDIATELY do the `[LOCAL]` second-session verify and disarm within the window. To RE-ARM before expiry, clear the old unit first (else `systemd-run` errors "unit already exists" and the original timer still fires): `sudo systemctl stop fw-rollback.timer; sudo systemctl reset-failed 'fw-rollback.*'` THEN re-issue `systemd-run --on-active=600 --unit=fw-rollback ...` (or a fresh `--unit`). Raise `--on-active` if your verify is slow.
  - After a second `[LOCAL]` session confirms access: **disarm the TIMER** — `sudo systemctl stop fw-rollback.timer && sudo systemctl reset-failed fw-rollback.timer fw-rollback.service 2>/dev/null || true`. (Stopping the `.service` does NOT cancel a pending one-shot — stop the timer.) After `stop` the transient unit DISAPPEARS, so `reset-failed` prints `Failed to reset failed state ...: Unit not loaded` — harmless (confirm via `list-timers | grep fw-rollback` = empty); the `2>/dev/null || true` suppresses it.
- **Rollback script** — `/usr/local/sbin/fw-rollback.sh` (open policies BEFORE flush, then restore backup):
  ```sh
  #!/bin/sh
  iptables  -P INPUT ACCEPT; iptables  -P FORWARD ACCEPT; iptables  -P OUTPUT ACCEPT
  ip6tables -P INPUT ACCEPT; ip6tables -P FORWARD ACCEPT; ip6tables -P OUTPUT ACCEPT
  iptables -F; iptables -X; ip6tables -F; ip6tables -X
  iptables-restore  < /root/iptables-backup.v4
  ip6tables-restore < /root/iptables-backup.v6
  ```
  (`iptables -F` alone is insufficient — it does not reset chain policy. The script resets policy then restores the backup; it does NOT touch sshd, because restoring the firewall alone restores reachability — the listener is untouched by iptables and new SSH = NEW, not INVALID.)
  - **§A1 stdin caveat — deliver scripts/configs via `printf` or base64, NOT a stdin heredoc, under a stateless one-shot controller.** When the whole command is piped through SSH (`ssh ... "base64 -d | sudo bash"` or `... <<'EOF'`), a `cat <<'EOF' > file` here-doc competes for the same stdin and truncates/corrupts the file. Use `printf '%s\n' '#!/bin/sh' 'iptables -P INPUT ACCEPT' ... > /usr/local/sbin/fw-rollback.sh` or base64-decode a single argument (stdin-safe). Applies anywhere this runbook shows a `cat <<'EOF'`.
  - **Port-change interaction (A1↔A2):** the snapshot holds only the SSH port open at A1 time (22). If A2 changes the port, this rollback would restore a ruleset blocking the NEW port = self-lockout. So change the port ONLY after the A1 fail-safe is disarmed, then re-run BOTH `iptables-save > /root/iptables-backup.v4` (+ `ip6tables-save > ...v6`) AND `sudo netfilter-persistent save` so backup and boot ruleset both match.
- **Choose build path from §2 detect:** if `iptables -S` shows an empty/default-ACCEPT chain (the expected fresh-VPS case) → use the fresh deterministic build below. If it already shows non-trivial rules or a DROP policy (a brownfield box — VPN/Docker/router; cross-check the §0.5 inventory) → this runbook does NOT auto-merge an unknown ruleset: insert the SSH ACCEPT ahead of any existing DROP immediately (`iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT`) to protect the session, then **STOP and ask the user** how to proceed (adopt / replace the existing firewall). Do NOT guess a merge, do NOT `iptables -F`, and follow the §0.5 brownfield adaptation matrix (preserve Docker/NAT chains, open workload ports, no `-P FORWARD DROP`).
  - **Timer discipline during user interaction.** Before any STOP-and-ask that may take unbounded time (brownfield adopt/replace, unknown port classification), the agent MUST either: (a) disarm the armed rollback timer (`systemctl stop fw-rollback.timer && systemctl reset-failed 'fw-rollback.*' 2>/dev/null || true`) if the firewall has NOT yet been changed from the snapshot, or (b) re-arm with a generous window (stop+reset-failed the old timer first, then `systemd-run --on-active=1800 --unit=fw-rollback ...`) if the change is already live. Never leave a short-fuse timer armed while waiting for human input.
- **IPv4 INPUT chain — deterministic build order (fresh path):**
  ```
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
  iptables -P INPUT DROP        # ONLY after the ACCEPT rules above exist
  iptables -P FORWARD DROP      # forwarding unused (ip_forward=0) → drop by default
  ```
  - **ESTABLISHED first:** loopback ACCEPT first; ESTABLISHED,RELATED early. Alone it does NOT admit a *new* SSH connection — the NEW-state dport-22 ACCEPT is mandatory.
  - **SSH-accept order:** first-match-wins. Never `-P INPUT DROP` before the SSH ACCEPT exists. On a live chain with an existing DROP, insert ahead: `iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT`.
  - **INVALID drop:** place AFTER loopback, BEFORE ESTABLISHED,RELATED. New SSH = NEW state, so no lockout.
  - **FORWARD drop:** set `-P FORWARD DROP` on the universal baseline (safe — `ip_forward=0`, no forwarding workload). A relay/VPN module that needs forwarding adds explicit `FORWARD` ACCEPT rules in the VPN/relay forwarding step. Cannot lock you out (forwarding ≠ your SSH session).
- **IPv6 mirror — iptables and ip6tables are INDEPENDENT.** Before `ip6tables -P INPUT DROP`, explicitly allow loopback, ESTABLISHED,RELATED, SSH, and essential ICMPv6 (RFC 4890 types 1,2,3,4,133,134,135,136) — else NDP/PMTUD break:
  ```
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A INPUT -p ipv6-icmp --icmpv6-type 1 -j ACCEPT   # repeat for 2,3,4,133,134,135,136 (NDP untracked => always INVALID, MUST precede the INVALID drop)
  ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP    # AFTER the ICMPv6 accepts
  ip6tables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
  ip6tables -P INPUT DROP
  ip6tables -P FORWARD DROP
  ```
  - v6 INVALID drop goes AFTER the ICMPv6 accepts: ICMPv6 NDP (types 133–136) is never conntrack-tracked → always classified INVALID, so an early INVALID drop kills NDP/PMTUD (ArchWiki, netfilter). ICMPv6 types 1,2,3,4,133–136 stay ACCEPT; `-P FORWARD DROP` mirrors v4. Use the canonical portable `-p ipv6-icmp --icmpv6-type N` (no `-m icmp6`). A global IPv6 (e.g. a `/48` on the NIC) makes this mirror mandatory, not optional.
  - Type 137 (Redirect) intentionally OMITTED — `accept_redirects=0` (RFC 4890 treats 137 as policy-defined). Echo (128/129) omitted (no inbound ping; echo-reply to the host's own pings returns via ESTABLISHED,RELATED).
- **Persistence** — `sudo apt-get install -y iptables-persistent` (pulls netfilter-persistent; restores `/etc/iptables/rules.v{4,6}` at boot). FIRST apt-install — REQUIRES a prior `sudo apt-get update` (§1 apt-index gate); on an empty index it fails `E: Package 'iptables-persistent' has no installation candidate` (rc=100) → firewall never persists. Confirm non-empty `Candidate` first. The debconf save prompt hangs a non-interactive agent — **preseed DECLINE auto-save** (correct — firewall isn't finalized) before installing:
  ```sh
  echo 'iptables-persistent iptables-persistent/autosave_v4 boolean false' | sudo debconf-set-selections
  echo 'iptables-persistent iptables-persistent/autosave_v6 boolean false' | sudo debconf-set-selections
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
  ```
  Persist ONLY after a second session confirms no lockout: `sudo netfilter-persistent save`.
  - **needrestart stderr is noise:** 26.04 `apt-get install` emits needrestart chatter to stderr — check the exit code, not stderr.
  - **Phase A makes NO further `iptables`/`ip6tables` changes after this save — EXCEPT an A2 SSH port change**, then re-run `sudo netfilter-persistent save` after opening the new port (else `rules.v4` allows only `:22` → any future reboot locks you out). fail2ban (A3) adds its OWN nft table NOT in `rules.v{4,6}`, regenerated at boot — expected, don't reconcile it. Post-reboot, verify against the persisted file (`diff <(iptables-save) /etc/iptables/rules.v4` ignoring `f2b-*` chains), not raw `iptables -S`.
- **Verify → Expected:** `iptables -S` and `ip6tables -S` show SSH ACCEPT before DROP; a NEW SSH session from the local machine succeeds; `systemctl list-timers | grep fw-rollback` shows nothing after disarm.

## A2 — SSH crypto hardening (drop-ins; unit is `ssh`, socket-activated on 24.04/26.04)

> **[26.04] OpenSSH 10.2p1 drift.** 26.04 runs OpenSSH **10.2p1** (not 9.6p1), OpenSSL 3.5.x, kernel 7.0. The Ciphers/MACs/HostKeyAlgorithms/PubkeyAcceptedAlgorithms below are all valid on 10.2p1 (`umac-128-etm@openssh.com`, `sk-*`, cert variants present); the only change vs 9.6p1 is KexAlgorithms (add the PQ default — see below). Always confirm with `ssh -Q kex|cipher|mac|key` before applying on an unknown release.

- **00-hardening.conf** (lexically earliest, beats `50-cloud-init.conf`):
  ```
  PasswordAuthentication no          # must be in 00-*, not 99-*
  KbdInteractiveAuthentication no    # second password path under UsePAM yes
  ```
  Also set `ssh_pwauth: false` in `/etc/cloud/cloud.cfg.d/99-disable-passwords.cfg` so cloud-init doesn't re-enable it.
  - **[soft] Same SSH-side config — `PasswordAuthentication no` stays.** SSH password auth is disabled in BOTH modes (brute-force surface). The difference is that `passwd -l root` is skipped and the admin user HAS a password — so the provider's web/VNC console (which is NOT SSH, it's a local TTY) still accepts login+password. SSH remains key-only.
  - **Neutralize the stock `50-cloud-init.conf` `PasswordAuthentication yes`, don't just out-rank it.** First-match-wins means `00-hardening.conf` already beats it, but the protection then rests SOLELY on `00-` sorting first — delete/rename `00-` and password auth silently turns back on. Defang the drop-in directly so it can't re-enable passwords if `00-` ever goes away:
    ```sh
    if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
      sudo sed -ri 's/^\s*PasswordAuthentication\s+yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/50-cloud-init.conf
    fi
    ```
    (If cloud-init is not installed, the file may be a leftover; neutralizing it is still correct and harmless.)
- **99-hardening.conf** (in-daemon policy & crypto):
  ```
  PermitRootLogin no                 # PREREQ: verified sudo user (see pre-sudo-user); [soft] use prohibit-password instead (see below)
  MaxAuthTries 3                     # ssh-agent offers count as attempts; use 4 or IdentitiesOnly yes if many keys
  LoginGraceTime 30                  # do NOT set 0 (MaxStartups DoS); CVE-2024-6387 (regreSSHion): upstream-vulnerable 8.5p1–9.8p1, Ubuntu backported the fix into 9.6p1-3ubuntu13.3+ (10.2p1 clean)
  ClientAliveInterval 300            # reap stale/half-open sessions (~10 min); does not affect key auth
  ClientAliveCountMax 2
  AllowGroups sshusers               # whitelist by GROUP, not single user (maintainable) — create the group + add the admin user FIRST (see below)

  # [26.04] mlkem768x25519-sha256 became the post-quantum DEFAULT in OpenSSH 10.0 (available since 9.9; 9.9's default was still sntrup761) — list it FIRST.
  # On 9.6p1 (24.04) it does not exist; drop the first token there. OpenSSH 9.9 ADDED a bare `sntrup761x25519-sha512` alias, but the `@openssh.com` form is KEPT and still ships in 10.0/10.2 — both valid; keep the `@openssh.com` token in the line below.
  KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
  HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  RequiredRSASize 3072
  ```
  - **`AllowGroups sshusers` — create the group and add the admin user BEFORE the reload, or you lock everyone out.** A group is the maintainable form of the whitelist: adding an operator becomes a `usermod`, not an sshd edit + reload (a lockout-capable action). Before reloading: `sudo groupadd -f sshusers && sudo usermod -aG sshusers <admin-user>`. Skip-if the group already exists, contains the admin user, and `99-hardening.conf` already uses `AllowGroups sshusers`. Verify: `id <admin-user>` lists `sshusers` and `sudo sshd -T | grep -i allowgroups` shows `allowgroups sshusers`; confirm a fresh `[LOCAL]` key login as `<admin-user>` in a second session before closing the current one (lockout-capable — same discipline as the rest of §A2). Rollback: keep the prior `AllowUsers <admin-user>` drop-in; on `sshd -t` failure do not reload.
  - **`@openssh.com` suffix on all three MACs is MANDATORY** — without it sshd rejects with `Bad SSH2 mac spec` and won't start (lockout).
  - **KexAlgorithms:** 6 entries on 9.6p1 (24.04); 7 on 10.x (24.04 set + `mlkem768x25519-sha256` FIRST). Do NOT add `ext-info-s`/`kex-strict-s-v00@openssh.com` (protocol markers, not config tokens — break sshd) or `gss-*` (GSSAPIKexAlgorithms only). Verify every token exists: `ssh -Q kex`.
  - **[26.04] Stop offering the NIST-P ECDSA host key via an explicit HostKey allow-list, NOT by commenting a line.** On a fresh 26.04 base config there is no literal `HostKey .../ecdsa` line to comment out (sshd loads default host keys implicitly), so "comment out the ecdsa HostKey" is a no-op. Instead declare the keys you DO want in `99-hardening.conf` — once any `HostKey` is set explicitly, only those are offered:
    ```
    HostKey /etc/ssh/ssh_host_ed25519_key
    HostKey /etc/ssh/ssh_host_rsa_key
    ```
    (On 24.04 where the base config DOES list the ecdsa HostKey, commenting it out still works; the explicit allow-list is the portable form.)
- **Host-key handling — never use `ssh-keygen -A` here** (it re-creates the ECDSA key you mean to drop). **Separate "drop ecdsa" from "regenerate everything":** on a fresh 26.04 the RSA host key is already 4096-bit and ed25519 already exists — only a surplus `ecdsa` key is present. Blowing away all keys (`rm /etc/ssh/ssh_host_*` + full regen) needlessly CHANGES the ed25519/RSA fingerprints (forcing a known_hosts re-pin for no security gain). Prefer the minimal path.
  - **Skip-if (idempotency — else every re-run churns the fingerprint and forces a fresh known_hosts re-pin, which a literal agent may misread as lockout):** skip this block if `/etc/ssh/ssh_host_ecdsa_key` is ABSENT AND `/etc/ssh/ssh_host_ed25519_key` exists AND the RSA host key is ≥3072-bit.
  - **Minimal path (preferred — good ed25519 + ≥3072 RSA already present, only ecdsa surplus):** drop just the ecdsa key, rely on the explicit `HostKey` allow-list above, trim weak moduli. No fingerprint change for the keys clients actually pin:
  ```
  rm -f /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_ecdsa_key.pub
  awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe && [ "$(wc -l < /etc/ssh/moduli.safe)" -ge 20 ] && mv /etc/ssh/moduli.safe /etc/ssh/moduli || rm -f /etc/ssh/moduli.safe
  systemctl restart ssh
  ```
  - **Keep GEX, guard the trim:** `diffie-hellman-group-exchange-sha256` IS offered and REQUIRES a usable `/etc/ssh/moduli`. Mozilla & ssh-audit (2025) retain it and `awk '$5>=3071'` is Mozilla's own trim (field 5 is the prime size in bits **minus 1** in practice — `moduli.5` loosely says "bits", but ssh-keygen records bits−1, so a 3072-bit prime stores 3071; Mozilla uses `$5>=2047` for 2048-bit); the `-ge 20` non-empty guard stops an over-trimmed/empty moduli from breaking GEX negotiation.
  - **Full-regen path (only if the existing keys are weak/missing — e.g. RSA <3072 or no ed25519):** as root:
  ```
  rm /etc/ssh/ssh_host_*
  ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
  ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
  awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe && [ "$(wc -l < /etc/ssh/moduli.safe)" -ge 20 ] && mv /etc/ssh/moduli.safe /etc/ssh/moduli || rm -f /etc/ssh/moduli.safe
  systemctl restart ssh
  ```
  **Regen changes the host fingerprint — handle `known_hosts` NOW, before any later new-session verify, or every subsequent `[LOCAL]` connection fails with `REMOTE HOST IDENTIFICATION HAS CHANGED` (a literal agent may misread this as a lockout and abort):** on the `[LOCAL]` controller run `ssh-keygen -R <host>` then reconnect once and accept/pin the new fingerprint. Do this immediately after the restart, before A2's key-only login check and any A3+ reachability test.
- **Apply — ONE canonical ordered sequence (do exactly this order):**
  1. Write `00-hardening.conf` + `99-hardening.conf` (incl. the explicit `HostKey` allow-list); neutralize the cloud-init `PasswordAuthentication yes` line. **Deliver file content via base64, not a stdin heredoc:** under a stateless one-shot controller use `echo <B64> | base64 -d | sudo tee /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null` — robust against the stdin-pipe corruption that hits `cat <<'EOF'`.
  2. `sudo sshd -t` (must exit 0 — this gate runs BEFORE any destructive key step; if non-zero, fix/remove drop-in, do NOT proceed).
  3. Regenerate/trim host keys (the host-key block above — minimal path on a fresh 26.04).
  4. ONE `sudo systemctl restart ssh` — applies both the host-key change AND the drop-in config. (When host keys change, `restart` is canonical, not `reload`.)
  5. `[LOCAL]`: `ssh-keygen -R <host>` then reconnect once to pin the new fingerprint. **(Paramiko-`AutoAddPolicy` controllers skip this — the new key is accepted automatically; for `plink` update the `-hostkey` fingerprint / registry cache instead. See Controller prerequisites.)**
  6. `[LOCAL]`: key-only login verify (below) BEFORE closing the original session.
  7. **Lock the root password (strict mode only) — ONLY after the non-root sudo user's key login is confirmed working in a separate session.** `PermitRootLogin no` closes SSH for root but leaves a live yescrypt hash in `/etc/shadow` (console/`su`/local-priv surface). Run `sudo passwd -l root` to lock it. Do NOT do this before the sudo user is proven, or you can lose all privileged access.
     - **[soft] Do NOT lock root and do NOT set `PermitRootLogin no`:**
       - Set `PermitRootLogin prohibit-password` in `99-hardening.conf` (no root-via-SSH-password; root CAN log in via provider console).
       - Keep the root password (do NOT `passwd -l root`) → provider web/VNC console login as root/admin recovers a lost SSH key.
       - Optionally set a STRONG root password if unset — generate ON THE BOX (anti-leak rule, §1): `set +o history; ROOT_PW="$(openssl rand -base64 18)"; printf 'root:%s\n' "$ROOT_PW" | sudo chpasswd; printf 'ROOT CONSOLE PASSWORD (store now, shown once): %s\n' "$ROOT_PW"; unset ROOT_PW`. Surface once, treat as secret (do not log/persist/summarize). Coordinate with the user.
       - **Trade-off:** soft mode leaves a local-TTY password surface (console only, NOT SSH-reachable). Console access = provider access = game over anyway; the real risk is a weak password — enforce a strong one.
  - **Transitioning soft → strict post-setup:** a re-run of §A2 in strict mode will: (1) change `PermitRootLogin` from `prohibit-password` to `no`, (2) run `passwd -l root` — this prepends `!` to the shadow hash, making the root console password issued during soft setup **permanently unusable** for console/VNC login (restorable via `passwd -u root` if needed). The admin-user console password (§1) remains valid. Inform the user: the root console password they stored is now inert; only the admin-user password works for console recovery.
  - **Port / ListenAddress** (only if changing the port — socket-activated on 24.04): open the new port in the firewall FIRST AND re-snapshot the A1 fail-safe backup (per §A1 persistence), then `sudo sshd -t && sudo systemctl daemon-reload && sudo systemctl restart ssh.socket` (`reload ssh` will NOT move the listener).
- **Verify → Expected:** `sudo sshd -t` exits 0; `sudo sshd -T | grep -Ei 'passwordauthentication|kbdinteractiveauthentication|permitrootlogin|maxauthtries'` shows the hardened values; a NEW key-only `[LOCAL]` session logs in BEFORE you close the current one — use `ssh -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -i <key> <admin-user>@<host> true` (`IdentitiesOnly` is REQUIRED — without it an agent with >3 loaded keys exhausts `MaxAuthTries 3` and the verify falsely fails). Optional: `ssh-audit <host>` clean.
- **A2 has no firewall-style auto-rollback — the open session is the SOLE safety net.** A drop-in can pass `sshd -t` yet still bar login (e.g. wrong `AllowGroups`, or the admin user not in `sshusers`). For extra safety, arm a revert timer before reload: `sudo systemd-run --on-active=300 --unit=ssh-revert sh -c 'rm -f /etc/ssh/sshd_config.d/00-hardening.conf /etc/ssh/sshd_config.d/99-hardening.conf; [ ! -f /etc/ssh/ssh_host_ed25519_key ] && ssh-keygen -A; systemctl reload ssh'` (This timer covers config errors; if host-key regen also failed, the `ssh-keygen -A` fallback regenerates default keys — including ecdsa, which is acceptable in a revert scenario where the goal is restoring connectivity, not maintaining hardening. On socket-activated SSH, new keys are picked up by the next connection automatically.), then cancel it (`systemctl stop ssh-revert.timer`) only after a fresh `[LOCAL]` login succeeds.
- **Rollback:** keep the prior drop-in content; on `sshd -t` failure do NOT reload — fix or remove the drop-in.

## A2.5 — Neutralize cloud-init so it can't undo your hardening on reboot

§A7 `apt-mark manual`s `cloud-init`/`netplan.io` — the `manual` flag prevents autoremove from pulling them, but does NOT prevent re-execution. The **service** still runs on boot, and on several providers cloud-init re-applies netplan (overwriting the §A4 MTU drop-in) and re-asserts users/SSH every boot — so any **future reboot** (user-initiated, kernel update) can silently revert parts of A2/A4. (The §A8 reboot now runs BEFORE A2/A4, so it cannot revert them — but cloud-init re-executes on EVERY boot unless disabled.)

- **Detect:** `cloud-init status 2>/dev/null`; `ls /etc/cloud/cloud.cfg.d/`; confirm whether the provider uses cloud-init first-boot-only (typical) vs every-boot network config (some).
- **Skip-if:** `cloud-init` not installed (`[26.04]` may ship only a leftover `50-cloud-init.conf`), OR the provider needs cloud-init every boot for networking (then DON'T disable — make your netplan drop-in win instead).
- **Apply (only after provisioning is complete and the network is persisted via netplan):**
  ```
  sudo touch /etc/cloud/cloud-init.disabled
  ```
- **Verify → Expected:** after any reboot, `cloud-init status` reports disabled and §A4 MTU / §A2 SSH settings are unchanged.
- **Rollback:** `sudo rm /etc/cloud/cloud-init.disabled`.

## A3 — fail2ban (24.04 default backend=systemd, banaction=nftables)

- **Backend (systemd) — do NOT override the backend.** 24.04/26.04 minimal has no rsyslog/`/var/log/auth.log`; a file backend silently matches nothing. Default is already `backend = systemd` in `/etc/fail2ban/jail.d/defaults-debian.conf`. Ensure `python3-systemd` installed.
  - **[26.04] the `asynchat` version-gate is a 24.04-only artifact.** The `No module named asynchat` crash hit fail2ban on Python 3.12; on 26.04 (Python 3.13+, newer fail2ban) it does not occur and `backend = systemd` works out of the box. Keep the `≥ 1.0.2-3ubuntu0.1` gate ONLY on 24.04; do NOT apply it on 26.04.
- **/etc/fail2ban/jail.local** (never edit jail.conf):
  ```
  [DEFAULT]
  ignoreself = true
  ignoreip   = 127.0.0.1/8 ::1 <SERVER_PUBLIC_IPV4>/32 <SERVER_PUBLIC_IPV6>/128 <ADMIN_IP_OR_CIDR>

  [sshd]
  enabled  = true
  maxretry = 3
  findtime = 600
  bantime  = 3600
  ```
  - **don't rely on `ignoreself` alone** — it covers the host's OWN local/interface IPs + loopback (the secondary-IP gap of upstream #3132 was FIXED in fail2ban 1.0.1, shipped on 24.04's 1.0.2 and 26.04's ≥1.1.0), but it does NOT cover a REMOTE admin's source IP. The load-bearing part is the explicit static admin IP. A dynamic admin IP = false safety → keep console fallback.
  - **NEVER write a literal `<ADMIN_IP_OR_CIDR>` / `<SERVER_PUBLIC_IPV4>` / `<SERVER_PUBLIC_IPV6>` into jail.local** — fail2ban ignores unparseable tokens, leaving the admin IP un-whitelisted ⇒ self-ban. If no STATIC admin IP is available, OMIT the token entirely and rely on the console fallback (note the risk).
  - **banaction:** leave the default `nftables`. Do NOT set obsolete `iptables-multiport` (creates a conflicting `ip filter` table). Override files must sort AFTER `defaults-debian.conf`. (fail2ban's `nftables` action uses its OWN dedicated table — this does NOT violate the §A1 "single backend / don't mix native nft" rule, which is about the table iptables-nft owns.)
- **Apply / Verify → Expected:** `systemctl restart fail2ban`; `fail2ban-client status sshd` active; `journalctl -u fail2ban` shows no backend errors. (`fail2ban-client get sshd ignoreip` lists the explicit IPs only — self-IPs from `ignoreself` won't appear; that's expected.)

## A4 — Network tuning (`/etc/sysctl.d/`; performance, not security unless noted)

> **Decision rule — do NOT agent-judge "only if…" conditions.** Every knob marked *context-dependent* / *module-only* / *raise only for X* is **SKIPPED in universal Phase A**, applied ONLY if a *collected* §I answer (`/root/vps-workload.conf`) calls for it (long-fat-network → 64 MiB buffers; high-connection/NAT → conntrack-max; relay/outbound-heavy → tcp_tw_reuse=1; provider clips MTU → MTU detect). No answer ⇒ keep the default, skip the block. Never stall, never guess the condition.

Write `/etc/sysctl.d/99-net-tune.conf`, then `sudo sysctl --system`:
```
# Socket buffer ceilings (autotuning caps, not allocations) — 16 MiB universal
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
# Queues / backlog
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
# Behavior
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
```
- **do NOT set `rmem_default`/`wmem_default = 2MB`** — TCP ignores them (uses tcp_rmem/tcp_wmem autotuning) and 2 MB inflates per-socket RAM. Leave the 212992 default.
- **16 MiB, not 64 MiB**, for a small VPS. Raise `rmem_max`/`wmem_max` to `67108864` ONLY in a confirmed long-fat-network module (10G, ≥100 ms RTT).
- **DROP these from a universal runbook** (no-op or harmful on defaults): `tcp_no_metrics_save` (forces cold-start, can reduce throughput), `tcp_fastopen` (no-op unless the daemon opts in), `udp_rmem_min/udp_wmem_min` (wmem variant inert on 24.04), explicit `tc qdisc ... fq quantum 2912` (kernel auto-sets quantum=2×MTU with `default_qdisc=fq`).
- **tcp_tw_reuse:** universal = kernel default `2` (loopback-only); set `1` only in the relay/outbound-heavy module. The NAT-incompatibility myth was `tcp_tw_recycle` (removed in 4.12, absent on 24.04). Affects only OUTBOUND connections.
- **conntrack-max — context-dependent, with an ordering trap:** kernel auto-derives it (typ. 65536 at 1–4 GB). Override only on high-connection/NAT hosts. The `nf_conntrack` module isn't loaded at boot on minimal hosts, so a plain sysctl silently fails to persist — fix both:
  ```
  echo nf_conntrack | sudo tee /etc/modules-load.d/nf_conntrack.conf
  printf 'ACTION=="add", SUBSYSTEM=="module", KERNEL=="nf_conntrack", RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/netfilter/nf_conntrack_max"\n' | sudo tee /etc/udev/rules.d/50-nf_conntrack-sysctl.rules
  ```
- **BBR — enable both `fq` qdisc AND BBR.** Write `/etc/sysctl.d/99-bbr.conf`:
  ```
  net.core.default_qdisc = fq
  net.ipv4.tcp_congestion_control = bbr
  ```
  Persist module: `echo tcp_bbr | sudo tee /etc/modules-load.d/bbr.conf`. Verify: `sysctl net.ipv4.tcp_available_congestion_control` lists `bbr` AND `...tcp_congestion_control` shows `bbr`.
  - **[INFO]** `default_qdisc=fq` only applies to interfaces brought up AFTER the sysctl runs; a NIC already up at boot (e.g. `net0`) keeps `pfifo_fast`. BBR works regardless on kernel 7.0 (the `fq` pacing requirement was a BBRv1-era concern), so this is cosmetic. If you want `fq` on the live NIC now: `sudo tc qdisc replace dev <iface> root fq` (or `netplan`/ifreload).
- **MTU detect — OPTIONAL; measure path MTU, never hardcode a fixed value. Default-skip (leave link MTU) if you cannot measure — a wrong MTU can break connectivity after `netplan apply`.**
  - Target: use a stable off-link anchor — the default gateway (`ip route | awk '/default/{print $3}'`) or `1.1.1.1`. Only run this if you have a reason to (provider known to clip MTU); otherwise SKIP and keep the default.
  - Measure: `tracepath -n <target>` → final `pmtu N`; confirm via DF-ping (`ping -M do -s 1472 -c2 <target>`, lower `-s` until success; MTU = payload + 28). If unmeasurable, SKIP — do not guess.
  - Persist `/etc/netplan/99-mtu.yaml` (`chmod 600`), match by MAC (name-only is unreliable under networkd):
    ```yaml
    network:
      version: 2
      ethernets:
        <iface>:
          match: { macaddress: "<MAC>" }
          set-name: <iface>
          mtu: <measured>
    ```
  - Apply: `sudo netplan try` (auto-reverts in 120 s) then `sudo netplan apply`; verify `ip link show <iface>`.
- **Post-tuning benchmark — compare against §2 baseline.** Append to `/root/net-baseline.txt`:
  ```sh
  echo "" >> /root/net-baseline.txt
  echo "=== POST-TUNING (BBR + 16M buffers) ===" >> /root/net-baseline.txt
  echo "congestion_control: $(sysctl -n net.ipv4.tcp_congestion_control)" >> /root/net-baseline.txt
  echo "rmem_max: $(sysctl -n net.core.rmem_max)" >> /root/net-baseline.txt
  echo "qdisc: $(sysctl -n net.core.default_qdisc)" >> /root/net-baseline.txt
  for url in https://proof.ovh.net/files/10Mb.dat http://speedtest.tele2.net/10MB.zip; do
    echo "download $url:" >> /root/net-baseline.txt
    curl -o /dev/null -s -w "  speed=%{speed_download} bytes/s  time=%{time_total}s\n" "$url" >> /root/net-baseline.txt
  done
  cat /root/net-baseline.txt
  ```
  Compare PRE vs POST speeds. BBR + larger buffers should show equal or better throughput (especially on high-latency links). If POST is slower — investigate: wrong MTU, packet loss, or provider QoS. Do NOT keep tuning that degrades throughput; revert the specific knob. Do NOT invoke the Ookla Speedtest CLI interactively (first-run EULA hangs an unattended agent); if required: `speedtest --accept-license --accept-gdpr -f json`.

## A5 — Kernel hardening (`/etc/sysctl.d/99-zz-kernel-harden.conf` — the `zz` prefix sorts AFTER distro `99-protect-links.conf`/`50-default.conf`, else `fs.protected_*` / redirects are silently re-overridden)

```
# Info-leak / process protections
kernel.kptr_restrict = 2           # use 1 if you profile with perf/eBPF kernel symbols
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1       # do NOT use 3 (irreversible, breaks debuggers)
kernel.randomize_va_space = 2
fs.suid_dumpable = 0               # also set `* hard core 0` + coredump.conf for full effect
kernel.unprivileged_bpf_disabled = 1   # only value 1 is one-way (irreversible until reboot); value 2 is reversible (can be lowered to 0/1) — Ubuntu default is 2; use 2 if unprivileged-BPF tooling runs
net.core.bpf_jit_harden = 2
# Link protections (distro default is 1 for BOTH fifos and regular; regular=2 extends to group-writable sticky dirs — do NOT lower regular below 1)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 1             # distro default is 1, not 2
fs.protected_regular = 2
# Network spoofing/redirect hardening — BOTH all AND default (CIS)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0      # NO net.ipv6...send_redirects key exists
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1            # default needed or hotplug NICs come up loose
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
```
- After apply: `sudo sysctl -w net.ipv4.route.flush=1; sudo sysctl -w net.ipv6.route.flush=1`.
- **`rp_filter=1` is lockout-capable (can sever an asymmetric-routed session) and A5 has NO auto-rollback — the open session is the sole net (as in A2).** Arm a LIVE kernel revert (a `sed`+`sysctl --system` revert silently no-ops if the value/format differs): `sudo systemd-run --on-active=300 --unit=rpf-revert sh -c 'sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2 net.ipv4.route.flush=1'`, apply, then do a fresh `[LOCAL]` session check; cancel the timer (`systemctl stop rpf-revert.timer`) only after it succeeds. (Value 2 = loose; the kernel uses max(all, per-interface) so 2 overrides any 1 on existing NICs.) Keep the file-edit `sed -i 's/rp_filter = 1/rp_filter = 2/' /etc/sysctl.d/99-zz-kernel-harden.conf` only as a SECONDARY persistence step, not the load-bearing revert.
- **Decision rule (do NOT agent-judge):** universal default = `1`. Use `2` (loose) ONLY if a collected interview answer says the host is multi-uplink/BGP/policy-routed/VPN. No answer ⇒ keep `1`; never infer from topology.
- **kexec lockdown — context-dependent, NOT universal:** `kernel.kexec_load_disabled = 1` only on hosts WITHOUT kdump/Livepatch (one-way until reboot; breaks crash-dump capture).
- **IP forwarding:** universal leaves `net.ipv4.ip_forward = 0` (do NOT set). VPN/relay module only sets `=1` — and **toggling ip_forward re-initializes IPv4 per-interface params to RFC1122 host / RFC1812 router defaults**, so in that module set `ip_forward` FIRST, then re-apply rp_filter/redirects.

## A6 — System maintenance

- **journald cap** `/etc/systemd/journald.conf.d/99-vps-cap.conf` (journald is the primary log on minimal — no rsyslog):
  ```
  [Journal]
  SystemMaxUse=500M
  SystemKeepFree=1G
  MaxRetentionSec=2week
  ```
  Ensure persistence first (`sudo mkdir -p /var/log/journal`), then `sudo systemctl restart systemd-journald`. (System* caps are no-ops on a volatile journal.)
- **needrestart non-interactive** (auto-restart services; does not auto-reboot for kernels; needs needrestart ≥ 3.6-7ubuntu4.1) — use a single-quoted heredoc so `$nrconf` is written literally (stateless executor: deliver via base64 → `base64 -d | sudo tee …`, per the §A1 stdin caveat):
  ```
  sudo tee /etc/needrestart/conf.d/50-autorestart.conf >/dev/null <<'EOF'
  $nrconf{restart} = 'a';
  EOF
  ```
- **time sync:** `timedatectl status` → "System clock synchronized: yes" / "NTP service: active"; if off `sudo timedatectl set-ntp true`. If chrony installed, disable timesyncd (never both).
- **AppArmor:** verify, do not disable — `sudo aa-status` shows profiles loaded/enforce. No `apparmor=0` in GRUB; don't mask the service.

## A6.5 — DNS hardening on systemd-resolved

Minimal Ubuntu uses `systemd-resolved` on `127.0.0.53` with no DNSSEC validation and cleartext DNS.

- **Skip-if:** a different resolver is in use, or the drop-in already exists with these values.
- **Apply:** write `/etc/systemd/resolved.conf.d/99-dns-hardening.conf`:
  ```
  [Resolve]
  DNSSEC=allow-downgrade
  DNSOverTLS=opportunistic
  ```
  then `sudo systemctl restart systemd-resolved`. (`allow-downgrade`/`opportunistic`, NOT `yes` — strict `yes` breaks on captive portals and resolvers without DoT. Raise to `yes` only when you control the upstream resolver.)
- **Verify → Expected:** `resolvectl status` shows the values on the link; `resolvectl query example.com` still resolves.
- **Rollback:** remove the drop-in, restart `systemd-resolved`.

## A7 — Cleanup (headless/virtualized; ALWAYS dry-run before purge)

> **Purges are irreversible — log them (mandatory, normal path) so the user can reinstall.** Append the resolved set to `/root/vps-purged-packages.log`. `apt-get -s purge` prints `Purg <pkg>` (and `Remv` for plain removals), so `awk '/^Remv/'` alone matches NOTHING on a purge → empty log. Match both, or read `dpkg.log`:
> ```sh
> # SIMULATED set, before purging:
> apt-get -s purge <pkgs> | awk '/^(Remv|Purg)/{print $2}' >> /root/vps-purged-packages.log
> # OR (more reliable) what ACTUALLY happened, after the purge:
> grep -E " (remove|purge) " /var/log/dpkg.log | awk '{print $4}' >> /root/vps-purged-packages.log
> ```

- `sudo apt-get purge --auto-remove fwupd` — safe on a guest (`systemd-detect-virt` ≠ none). **Skip on bare-metal/dedicated** (fwupd = LVFS firmware path).
- Verify `apt-cache rdepends --installed udisks2`, then `sudo apt-get purge --auto-remove udisks2`. Often already absent on server.
- **multipath-tools — GATE, abort if any positive (root on multipath ⇒ unbootable after purge):** `findmnt -no SOURCE /` (not `/dev/mapper/mpath*`); `lsblk` (no `mpath` above `/`); `multipath -ll` empty; `dmsetup ls --target multipath` → "No devices found". Only then:
  ```
  systemctl disable --now multipathd.service multipathd.socket
  apt-get purge -y multipath-tools multipath-tools-boot
  apt-get autoremove -y
  update-initramfs -u -k all
  ```
- `apt-get -s purge packagekit` (dry-run) then real purge. unattended-upgrades does NOT depend on it. On 26.04 there is NO `packagekit-tools` package (`apt-cache policy packagekit-tools` is empty); apt aborts the WHOLE command (rc=100) on a single unfound name → packagekit is left installed. Purge ONLY `packagekit`. Conservative alt: `systemctl mask --now packagekit packagekit-offline-update`.
- `sudo apt-get -y purge apport apport-symptoms whoopsie` (optionally `ubuntu-report popularity-contest`). Install `systemd-coredump` if you still want post-mortem dumps.
- `sudo apt-get purge -y sysstat`. To keep tools, set `ENABLED="false"` in `/etc/default/sysstat` + disable the timers (the systemd `sysstat-collect.timer` is NOT gated by `ENABLED=false` — that flag gates the cron/SA1 path; the timer is a separate unit, compounded by first-boot presets, LP #2066117 — confirm stopped).
- **Autoremove safety — guard cloud-init/kernel:** `sudo apt-mark manual cloud-init netplan.io software-properties-common` FIRST (autoremove only targets `auto`-flagged packages; `manual` protects them without blocking security updates — unlike `hold`, which silently excludes the package from unattended-upgrades). Dry-run `sudo apt-get -s autoremove --purge`, inspect the Remv/Purg list, match against `uname -r` (a manually-booted old kernel can be removed). Only then run for real.
  Guard for absent packages: `for pkg in cloud-init netplan.io software-properties-common; do dpkg -l "$pkg" 2>/dev/null | grep -q '^ii' && sudo apt-mark manual "$pkg"; done` (skips packages not installed — `apt-mark manual` on an absent package errors on some 26.04 images).
  - **[26.04] `--auto-remove` cascades WIDE — review the dry-run, it removes more than you target.** On 26.04 the packagekit/apport purges + autoremove can pull in: `ubuntu-server` (metapackage), `jq`, `software-properties-common` (⇒ no more `add-apt-repository`), `appstream`, `modemmanager`/`libqmi`/`libmbim`, and `ufw`. If you need any of these, `sudo apt-mark manual <pkg>` BEFORE the purge (or reinstall after, from the log). (software-properties-common is marked manual in the guard above; on 26.04 it is still pulled by the packagekit purge cascade despite the flag — verify it survives, reinstall if not: `sudo apt-get install -y software-properties-common`) Similarly verify cloud-init: `dpkg -l cloud-init 2>/dev/null | grep -q '^ii' && sudo apt-mark manual cloud-init || true` (the base package may only exist as `cloud-initramfs-*` variants on some images). Always read the simulated set first; never blind-run `purge --auto-remove`.
- **[OPTIONAL] snapd:** snapd is not purged on the universal baseline; on a minimal headless VPS it's usually dead weight (the `snapd` daemon + `snap-repair.timer`). If no workload needs snaps: `sudo systemctl disable --now snapd.socket snapd.service snapd.seeded.service 2>/dev/null; sudo apt-get purge -y snapd && sudo apt-get autoremove -y` (log purged set per the top note). Skip if snaps are in use.
- `sudo apt-get clean` and `sudo journalctl --vacuum-size=500M` (matches the §A6 `SystemMaxUse=500M` cap — a one-time trim below the cap just churns back up; the suffix is REQUIRED — bare `--vacuum-size` errors).
- **Reset failed units — clear stale failed units after purge.** Purging a service (e.g. `apport.service`, `multipathd-queueing.service`) leaves it in `systemctl --failed` as `not-found`, which makes the §V "no new failed units" check FALSE-fail. After purges run: `sudo systemctl reset-failed` (or target specific units: `sudo systemctl reset-failed apport.service multipathd-queueing.service`). Then re-check `systemctl --failed` is clean.

## A8 — Full upgrade + reboot (runs after A1; disarm fw-rollback timer first)

- **PRE-GATE (all must hold before rebooting):** no `fw-rollback` timer armed (`systemctl stop fw-rollback.timer && systemctl reset-failed 'fw-rollback.*' 2>/dev/null || true`); firewall persisted in A1 — verify `/etc/iptables/rules.v4` + `rules.v6` exist and are non-empty, else the box boots default-ACCEPT/empty = silently unhardened. `rules.v{4,6}` are `0640 root:root` — read WITH `sudo` (`sudo wc -l /etc/iptables/rules.v4 /etc/iptables/rules.v6`); a bare `wc -l`/`cat` as non-root returns `Permission denied` (0 lines), misread as not-persisted.
- **Assert the PERSISTED ruleset opens the CURRENT SSH port** (not just that rules.v4 is non-empty): `sudo grep -- "--dport 22" /etc/iptables/rules.v4` (and `rules.v6` if v6 SSH) MUST return a match. ABORT the reboot if absent — the rollback timer does not survive a reboot. (SSH port is still 22 at this stage — A2 has not run yet.)
- **Full upgrade:**
  ```
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  apt-get update
  apt-get full-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
  ```
  `--force-confold` keeps provider-shipped configs intact (hardening drop-ins are not yet written at this stage; this protects cloud-init/netplan configs from being replaced). Reconcile any `*.dpkg-dist` later. `full-upgrade` MAY remove packages — review the list.
- **HWE kernel (OPTIONAL):** on 24.04 the default GA 6.8 is supported to Apr 2029; install HWE only if hardware needs it: `sudo apt install --install-recommends linux-generic-hwe-24.04`. **[26.04]** the box ships kernel **7.0** (`7.0.0-15-generic`); `full-upgrade` on a fresh image will itself pull a newer point kernel (e.g. `7.0.0-22`) and set `/var/run/reboot-required` — expected, that's why A8 reboots. Never pin a specific point kernel (short EOL) — track the rolling metapackage.
  - **[26.04] cloud-init may be ABSENT:** 26.04 may have only a leftover `50-cloud-init.conf` + `netplan.io`, with no `cloud-init` package. `sudo apt-mark hold cloud-init` is harmless when the package is absent (no-op); `netplan.io` is still held. Don't treat "cloud-init not installed" as an error.
- **Reboot tracking — anchor on boot_id changing (not uptime):**
  ```
  PRE=$(cat /proc/sys/kernel/random/boot_id)
  sudo reboot
  # from the LOCAL machine: poll SSH (timeout ~600s, retry every few s) until it answers,
  # then require: [ "$(ssh host cat /proc/sys/kernel/random/boot_id)" != "$PRE" ]
  ```
  Then liveness: `systemctl is-system-running` (running/degraded). After confirmed: re-verify firewall loaded (`iptables -S` shows the persisted rules).
  - **If SSH never reconnects within the timeout: STOP. The box may be bricked (bad MTU, broken upgrade, unpersisted firewall). You have no connection — rollback is impossible. Escalate to the user with provider-console recovery instructions.** Do not loop indefinitely; do not claim success.
- **Post-reboot re-verification pass:** confirm firewall loaded (`iptables -S` shows persisted rules, SSH ACCEPT before DROP), system healthy (`systemctl is-system-running` = running/degraded), SSH reachable from `[LOCAL]`. No sshd/sysctl/fail2ban checks needed — A2–A7 have not run yet. Proceed to A2.

## A9 — Unattended security updates (enable LAST, after reboot verified)

- `/etc/apt/apt.conf.d/20auto-upgrades`:
  ```
  APT::Periodic::Update-Package-Lists "1";
  APT::Periodic::Unattended-Upgrade "1";
  APT::Periodic::AutocleanInterval "7";
  ```
- **do NOT overwrite `/etc/apt/apt.conf.d/50unattended-upgrades` — use a separate drop-in.** The shipped `50unattended-upgrades` holds `Unattended-Upgrade::Allowed-Origins` (security patterns, e.g. `o=Ubuntu,a=${distro_codename}-security`); replacing it with just the override lines SILENTLY KILLS Allowed-Origins → installs nothing. apt reads every file and the higher-numbered wins per key, so put overrides in their own file, leave `50-` untouched. Write `/etc/apt/apt.conf.d/52-unattended-upgrades-local`:
  ```
  Unattended-Upgrade::Automatic-Reboot "false";          # agent controls reboots
  Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
  Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
  ```
  Requires `apt-get install -y unattended-upgrades`. Because auto-reboot is off, the agent (or operator) MUST watch `/var/run/reboot-required` and schedule reboots, or kernel/libc/openssl fixes stay inactive.
- **Verify → Expected:** `unattended-upgrade --dry-run --debug` shows the security origin enabled AND `Allowed-Origins` listed. **[26.04]** the codename is `resolute`, so the dry-run shows e.g. `Allowed origins: o=Ubuntu,a=resolute-security,...`. Any codename-hardcode in a config (there should be none — patterns use `${distro_codename}`) must match the running release.

## A10 — Detection & monitoring (universal; can run any time after §A3, parallel-safe)

> **Ordering note (applies to §A10–§A12):** these blocks follow A9 in execution. §A11.1/§A11.2 change the firewall — re-run `netfilter-persistent save` after applying. §A12.1 module blacklist takes full effect at next reboot (or on next `modprobe` attempt). §A12.2 mount options take effect via `mount -o remount`. No second reboot required in Phase A — changes either take effect immediately or at the next user-initiated/kernel-update reboot.

Phase A's only detective control otherwise is fail2ban (reacts to *failed* auth only) — nothing watches a *successful* intrusion, config tampering, or privesc, and there's no forensic trail.

### A10.1 — auditd (forensic trail)
- **Skip-if:** `systemctl is-active auditd` is `active` AND `/etc/audit/rules.d/99-vps.rules` exists.
- **Apply:**
  ```
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins
  sudo tee /etc/audit/rules.d/99-vps.rules >/dev/null <<'EOF'
  -w /etc/ssh/sshd_config -p wa -k sshd_config
  -w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
  -w /etc/sudoers -p wa -k sudoers
  -w /etc/sudoers.d/ -p wa -k sudoers
  -w /etc/passwd -p wa -k identity
  -w /etc/shadow -p wa -k identity
  -w /etc/group -p wa -k identity
  -w /root/.ssh/ -p wa -k ssh_keys
  -w /etc/cron.d/ -p wa -k cron
  -w /etc/crontab -p wa -k cron
  -a always,exit -F arch=b64 -F euid=0 -S execve -k root_exec
  EOF
  sudo augenrules --load
  ```
  (Per the §A1 stdin caveat under a stateless executor: deliver the rules file via base64 → `base64 -d | sudo tee …`, not a piped heredoc, if your controller pipes stdin.)
- **Verify → Expected:** `sudo auditctl -l` lists the rules; `sudo ausearch -k sshd_config` returns events after touching a watched file.
- **Rollback:** `sudo rm /etc/audit/rules.d/99-vps.rules && sudo augenrules --load`.

### A10.2 — Successful-login notification (PAM)
- **Skip-if:** `/usr/local/sbin/ssh-login-notify.sh` exists and the `pam_exec` line is in `/etc/pam.d/sshd`.
- **Apply** (stateless executor: deliver the script via base64 → `base64 -d | sudo tee …`, per the §A1 stdin caveat):
  ```
  sudo tee /usr/local/sbin/ssh-login-notify.sh >/dev/null <<'EOF'
  #!/bin/sh
  [ "$PAM_TYPE" = "open_session" ] || exit 0
  MSG="SSH login: user=$PAM_USER from=$PAM_RHOST on $(hostname) at $(date -Is)"
  logger -t ssh-login-notify "$MSG"
  if [ -n "$NOTIFY_WEBHOOK" ]; then
    curl -fsS --max-time 5 -d "$MSG" "$NOTIFY_WEBHOOK" >/dev/null 2>&1 || true
  fi
  exit 0
  EOF
  sudo chmod 700 /usr/local/sbin/ssh-login-notify.sh
  grep -q ssh-login-notify /etc/pam.d/sshd || echo 'session optional pam_exec.so seteuid /usr/local/sbin/ssh-login-notify.sh' | sudo tee -a /etc/pam.d/sshd >/dev/null
  ```
  (Set `NOTIFY_WEBHOOK` in the script's environment for an ntfy/Telegram/Slack URL; if §A11 egress is restrictive, allow that host:443.)
- **Verify → Expected:** a fresh `[LOCAL]` login then `journalctl -t ssh-login-notify -n1` shows the login line. `session optional` is deliberate — a notifier failure must NEVER block login.
- **Rollback:** remove the `pam_exec` line; delete the script.

### A10.3 — AIDE file-integrity baseline (OPTIONAL — heavier)
- **Skip-if:** small/throwaway box, or the user declines (daily scan is real IO/CPU on 1 vCPU). Recommended for long-lived hosts.
- **Apply:** `sudo apt-get install -y aide aide-common`; `sudo aideinit`; `sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db`; rely on the packaged `dailyaidecheck.timer`. **Initialize the baseline LAST** — AFTER all Phase A blocks (A8 upgrade included) AND after any A12 file-mutating blocks (modprobe.d, fstab) — so it reflects the hardened state; else `aide --check` false-positives on the A12 changes.
- **Verify → Expected:** `sudo aide --check` returns no unexpected changes on a clean box.
- **Rollback:** `sudo apt-get purge --auto-remove aide aide-common` (log per §A7).

## A11 — Egress control (A11.1 universal = visibility; A11.2 optional = containment)

§A1 firewalls INPUT/FORWARD but leaves `OUTPUT ACCEPT` open — the primary **exfiltration / C2 path** post-compromise. Egress lockdown is staged here (omitted from §A1 on purpose — it breaks apt/DNS/updates without knowing the workload).

> **Lockout note:** a restrictive `OUTPUT` policy does NOT sever your inbound SSH session (SSH replies are `ESTABLISHED,RELATED`, allowed by the first OUTPUT rule); it CAN break outbound services (apt, DNS, webhook, NTP). Arm a revert timer and verify `apt-get update` before persisting.

### A11.1 — Default everywhere: log dropped inbound (scan visibility)
Add as the **last INPUT rule, immediately before `-P INPUT DROP`** (mirror into ip6tables). Guard each append with `-C` so re-runs stay idempotent (`-A` always appends; `-C` tests existence — iptables-nft on 24.04/26.04 supports `-C` reliably):
```
iptables  -C INPUT -m limit --limit 5/min -j LOG --log-prefix "ipt-drop-in: "  --log-level 4 2>/dev/null || iptables  -A INPUT -m limit --limit 5/min -j LOG --log-prefix "ipt-drop-in: "  --log-level 4
ip6tables -C INPUT -m limit --limit 5/min -j LOG --log-prefix "ipt6-drop-in: " --log-level 4 2>/dev/null || ip6tables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "ipt6-drop-in: " --log-level 4
```
- **Verify → Expected:** `journalctl -k | grep ipt-drop-in` shows hits after an external port scan; rate-limited so it can't flood the journal.
- **Re-persist:** changes the saved ruleset → re-run `sudo netfilter-persistent save`.

### A11.2 — Restrictive OUTPUT allow-list (OPTIONAL; strict + known egress profile only)
- **Skip-if:** egress is unknown/dynamic (keep A11.1 only), or a forwarding workload (VPN/relay) needs arbitrary egress.
- **Apply (arm the revert timer FIRST):**
  ```
  sudo systemd-run --on-active=300 --unit=egress-revert sh -c 'iptables -P OUTPUT ACCEPT; ip6tables -P OUTPUT ACCEPT'
  # -C guard each append so re-runs stay idempotent (mirror for ip6tables as needed):
  iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o lo -j ACCEPT
  iptables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -C OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
  iptables -C OUTPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
  iptables -C OUTPUT -p udp --dport 123 -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
  iptables -C OUTPUT -p tcp --dport 80  -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT
  iptables -C OUTPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
  iptables -P OUTPUT DROP
  ```
  - **DHCP caveat:** if the VPS runs a DHCP client with a finite lease (check `networkctl status` / netplan `dhcp4: true`), also allow outbound `udp --sport 68 --dport 67` (`-C`-guarded) or lease RENEWAL fails SILENTLY and the box drops off the network at lease expiry (delayed outage). Unnecessary if networking is cloud-init/static (no DHCP client).
  Then prove egress works (`sudo apt-get update`, `resolvectl query example.com`, webhook if used). Only then disarm: `sudo systemctl stop egress-revert.timer && sudo systemctl reset-failed 'egress-revert.*' 2>/dev/null || true`, and `sudo netfilter-persistent save`.
- **Verify → Expected:** `iptables -S OUTPUT` shows the allow-list before `-P OUTPUT DROP`; apt/DNS/NTP work; `curl --max-time 5 http://<random-host>:4444` times out.
- **Rollback:** the armed `egress-revert` timer, or `iptables -P OUTPUT ACCEPT; ip6tables -P OUTPUT ACCEPT` and re-save.

## A12 — OS-level hardening (OPTIONAL strict-only — review breakage notes per item)

### A12.1 — Disable unused/dangerous kernel modules
- **Skip-if:** any listed module is in use (`lsmod | grep -E 'dccp|sctp|rds|tipc'`), or the workload needs USB storage / exotic filesystems.
- **Apply:** write `/etc/modprobe.d/99-vps-blacklist.conf`:
  ```
  install dccp /bin/true
  install sctp /bin/true
  install rds /bin/true
  install tipc /bin/true
  install cramfs /bin/true
  install freevxfs /bin/true
  install jffs2 /bin/true
  install usb-storage /bin/true
  ```
  (`install … /bin/true` is reliable — a bare `blacklist` only stops autoload, not explicit `modprobe`.)
- **Verify → Expected:** `modprobe -n -v dccp` prints `install /bin/true`.
- **Rollback:** remove the file.

### A12.2 — Mount hardening for world-writable tmp dirs
- **Skip-if:** `/tmp` already hardened, or the workload runs executables from `/tmp` (some build/CI/snap flows do — `noexec` breaks them).
- **Apply:**
  ```
  grep -q '/dev/shm' /etc/fstab || echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /etc/fstab
  sudo mount -o remount /dev/shm
  ```
  Prefer a `tmp.mount`/fstab entry with `nodev,nosuid,noexec` on `/tmp` and `/var/tmp` too. **Caveat:** `noexec /tmp` breaks some apt maintainer scripts and snap; test before persisting, drop `noexec` on `/tmp` if it breaks (keep `nodev,nosuid`).
- **Verify → Expected:** `findmnt /dev/shm` shows `nodev,nosuid,noexec`; apt still installs.
- **Rollback:** remove the fstab line, remount.

### A12.3 — `hidepid` on /proc (OPTIONAL — can break some monitoring agents)
- **Skip-if:** a monitoring/APM agent needs to read other users' `/proc`.
- **Apply:** mount `/proc` with `hidepid=2` via fstab + a systemd drop-in. Test the workload first.
- **Verify → Expected:** a non-root user sees only their own PIDs in `ps aux`.
- **Rollback:** remove the option, remount.

---

# §I — INTERVIEW (run in parallel with A2–A7; agent↔user, off-box)

**Interleave** the interview with A2–A7 steps (the A8 reboot after A1 is a natural pause for the first question batch; ask remaining questions in gaps between Apply blocks, never block Phase A waiting on an answer). Persist answers to `/root/vps-workload.conf` on the box (survives the A8 reboot — it's on disk, not session state). **Concrete absent-user gate:** if no workload answer has been given by the time Phase A is fully verified, proceed as **B-none** — do NOT block, do NOT guess a workload.

Questions (hardening mode already collected in §1 — do NOT re-ask here):
1. Primary workload (web / VPN / relay / fileshare / none-yet)?
2. Public ports needed?
3. Is this RF/censorship-facing (relay/VPN under restrictive network)?
4. Expected traffic profile (long-haul/high-BDP? high connection rate?) — drives the context-dependent net values.

---

# PHASE B — WORKLOAD MODULES (conditional; only after Phase A verified + answers collected)

Read the workload + any module knobs from `/root/vps-workload.conf` (written in §I). Cutoff: whatever is in that file at the instant Phase A verify completes decides the module; a later answer is ignored unless the user re-invokes. Each module is additive over the universal baseline. Install workload components (Docker, nginx, WireGuard, …) only here, only if the chosen workload needs them.

- **B-none** — stop after Phase A. The box is hardened, tuned, clean, auto-patched.
- **B-web** — open 80/443 (host firewall AND cloud SG); reverse proxy (caddy/nginx/traefik) + TLS; deploy in Docker if chosen. No IP forwarding.
- **B-relay / B-vpn** — enable forwarding via the §A5 IP-forwarding step (set `ip_forward=1` FIRST, then re-apply rp_filter/redirects); `tcp_tw_reuse=1` (outbound-heavy); consider conntrack tuning (never set `nf_conntrack_tcp_timeout_established` below the kernel `tcp_keepalive_time` default of 7200 s, nor below RFC 5382's 7440 s floor). Long-haul → raise socket buffers to 64 MiB here.
- **B-fileshare** — open the share's ports; size socket buffers to transfer profile; mind conntrack for many clients.

### RF anti-censorship sub-module (relay/VPN under restrictive network only)
- **ICMP — never blanket-DROP ICMP/ICMPv6.** IPv4 PMTUD = ICMP **type 3 code 4** (frag-needed). Keep ESTABLISHED,RELATED ACCEPT before any ICMP DROP. Allow IPv4 frag-needed/echo-reply/time-exceeded; IPv6 packet-too-big(2)/time-exceeded/destination-unreachable + NDP 133–136 (type 137 Redirect omitted — `accept_redirects=0`; matches §A1). Add `-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`. (Dropping IPv6 type 2 = total failure past a smaller-MTU hop — routers never fragment.)
- **Blocklist (ipset)** — hash:net blocklist with integrity check, atomic swap, and relay/mgmt whitelist re-asserted on EVERY load:
  ```sh
  curl -fsSL -o /tmp/ru-agg.zone https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone
  curl -fsSL https://www.ipdeny.com/ipblocks/data/aggregated/MD5SUM | grep ru-aggregated.zone | (cd /tmp && md5sum -c -) || exit 1
  ipset create rf_block_tmp hash:net family inet hashsize 8192 maxelem 131072 -exist; ipset flush rf_block_tmp
  while read n; do [ -n "$n" ] && ipset add rf_block_tmp "$n" -exist; done < /tmp/ru-agg.zone
  ipset create rf_block hash:net family inet -exist
  ipset swap rf_block_tmp rf_block; ipset destroy rf_block_tmp     # kernel-atomic
  iptables -C INPUT -s <RELAY_IP>/32 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s <RELAY_IP>/32 -j ACCEPT
  iptables -C INPUT -m set --match-set rf_block src -j DROP 2>/dev/null || iptables -A INPUT -m set --match-set rf_block src -j DROP
  ```
  Refresh daily via systemd timer. Fail HARD on MD5 mismatch (integrity check against truncation/corruption, NOT against source compromise — MD5 is cryptographically broken and the checksum is served from the same origin as the data; never swap a partial/corrupt set). **Re-assert the whitelist every load** — guards against a future list revision that contains your own relay/management IP.
  - **Persist the set or the boot-time `iptables-restore` of the `--match-set rf_block` rule fails / dangles:** the rf_block ipset MUST be restored BEFORE the iptables rules at boot. Either rely on the daily-refresh timer running early (`Before=netfilter-persistent.service`), or add an `ipset-restore` unit: `ipset save > /etc/iptables/ipset.rules` and a systemd oneshot (`ExecStart=/sbin/ipset restore -f /etc/iptables/ipset.rules`, ordered `Before=netfilter-persistent.service`). After adding the `--match-set rf_block` DROP rule, run `sudo netfilter-persistent save` so it lands in `rules.v4` (the ipset must restore BEFORE that rule loads — hence the ordering above). Verify after reboot: `ipset list rf_block` non-empty AND the iptables match-set rule present.
- **443 rate-limit — do NOT use `-m recent` on 443** (one source IP fronts many legit clients via CGNAT/proxy; HTTP/2 coalescing → self-DoS). Use per-IP `-m hashlimit`/`-m connlimit`, gated on `--ctstate NEW`, with ESTABLISHED,RELATED ACCEPT first. Reserve `-m recent` for low-rate SSH brute-force.

---

# §V — VERIFICATION MATRIX (verify behavior, not config text)

**On-fail policy:** lockout-capable rows (SSH login, SSH syntax/policy, firewall order, firewall reachability, rollback disarmed) → on fail, do NOT proceed: fix or run the block's rollback, re-verify; if still failing, abort per §0. All other rows (BBR, sysctl, MTU, journald, fail2ban, cleanup, auto-updates) → on fail, REMEDIATE in place (re-apply the block) and re-verify; only escalate to the user if a remediation attempt also fails. A cosmetic miss (e.g. `systemctl is-system-running` = `degraded` from an unrelated unit) is not an abort trigger — note it and continue.


| Area | Command (run where noted) | Expected |
|---|---|---|
| SSH syntax | `sudo sshd -t` | exit 0 |
| SSH effective policy | `sudo sshd -T \| grep -Ei 'passwordauthentication\|permitrootlogin\|maxauthtries\|macs\|kexalgorithms'` | hardened values; `permitrootlogin no` (strict) or `prohibit-password` (soft) |
| SSH login `[LOCAL]` (NEW session) | `ssh -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -i <key> <admin-user>@<host> true` | succeeds |
| Firewall order | `iptables -S` / `ip6tables -S` | SSH ACCEPT before DROP; v6 mirrored |
| Firewall reachability (LOCAL machine) | new SSH connection | succeeds |
| Rollback disarmed | `systemctl list-timers \| grep fw-rollback` | empty |
| fail2ban | `fail2ban-client status sshd` | active, jail loaded |
| BBR | `sysctl net.ipv4.tcp_congestion_control` | `bbr` |
| sysctl applied | `sudo sysctl --system` then spot-check keys | values match |
| MTU | `ip link show <iface>` | measured MTU |
| journald cap | `journalctl --disk-usage` | within cap |
| Reboot completed `[LOCAL]` | boot_id (captured `[LOCAL]` pre-reboot) changed + `systemctl is-system-running` | new UUID; running/degraded |
| Auto-updates | `unattended-upgrade --dry-run --debug` | security origin + `Allowed-Origins` enabled (`resolute-security` on 26.04) |
| Root login (strict) | `sudo passwd -S root` | `L` (locked); SSH-as-root → `Permission denied (publickey)` |
| Root login (soft) | `sudo passwd -S root`; `sudo sshd -T \| grep permitrootlogin` | `P` (password set, not locked); `permitrootlogin prohibit-password`; SSH-as-root with password → rejected; console login with password → succeeds |
| Cleanup | `systemctl --failed` (after `systemctl reset-failed`); `df -h` | no failed units (purged-service stubs cleared); junk gone |
| Console password not leaked | `history \| grep -c <user>`; transcript review | `0`; absent from files and logs |
| AllowGroups login | `[LOCAL]` new key session as admin | succeeds; `sshd -T \| grep allowgroups` = `sshusers` |
| cloud-init neutralized | `cloud-init status` (after any reboot) | disabled; A2/A4 unchanged |
| auditd | `sudo auditctl -l` | rules listed; `ausearch -k sshd_config` returns events |
| Login notify | login → `journalctl -t ssh-login-notify -n1` | login line present |
| Inbound-drop logging | `journalctl -k \| grep ipt-drop-in` | scan hits logged, rate-limited |
| Egress (if restrictive) | `apt-get update`; `curl --max-time 5 http://<host>:4444` | apt works; high-port egress times out |
| Module blacklist | `modprobe -n -v dccp` | `install /bin/true` |
| Mount hardening | `findmnt /dev/shm` | `nodev,nosuid,noexec`; apt installs |

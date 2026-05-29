# VPS-PREP-RUNBOOK — Universal Ubuntu Hardening, Tuning & Cleanup (24.04 / 26.04)

**Audience:** an AI agent driving a fresh VPS — or hardening one that already runs a workload (see §0.5 pre-flight discovery) — **remotely over SSH from a local machine**.
**Goal:** turn a default, scan-magnet VPS into a hardened, max-throughput, junk-free host ready for *any* workload — without pre-installing workload components (Docker etc. install only when a workload needs them).
**Target:** Ubuntu 24.04 LTS (kernel 6.8 GA, OpenSSH 9.6p1, iptables-nft) **and Ubuntu 26.04 (`resolute`; kernel 7.0, OpenSSH 10.2p1, OpenSSL 3.5.x)**.

> Items marked **[26.04]** capture version-specific drift — read those caveats.

> **Hardening mode — `strict` (default) vs `soft` (beginner-friendly).** Items marked **[soft]** show how a step differs in soft mode. Soft mode preserves the ability to log into the server from the provider's web/VNC console using a login + password — a critical safety net for users who may lose their SSH key. The agent MUST ask the user which mode to use at the start of the Interview (§I) and persist the choice to `/root/vps-workload.conf` as `HARDENING_MODE=strict|soft`. If the user does not answer or is unsure → default to **soft** (safer for beginners; can be tightened later with a single re-run of §A2).

> **Version-drift protocol.** On ANY release: before applying §A2 crypto, confirm each token exists with `ssh -Q kex`, `ssh -Q cipher`, `ssh -Q mac`, `ssh -Q key`; before applying §A4/§A5, a non-existent sysctl key errors on `sysctl --system` (drop the key, don't fight it). Treat per-version notes (`[26.04]`) as the adaptation, not an abort. The §1 OS-check accepts 24.04 and 26.04 and otherwise warns + adapts rather than aborting silently.

---

## §0 — AGENT CONTRACT (read before executing anything)

- **You run remotely over SSH.** A bad firewall/SSH change can lock you out permanently. Treat every step touching `iptables`/`ip6tables`/`sshd`/SSH `Port` as lockout-capable.
- **Lifelines — what actually saves you:** the load-bearing fail-safe is the **server-side `systemd-run` revert timer** armed before each risky change, NOT a "session you keep open". A stateless one-shot controller (CLI agent, paramiko, `plink`) opens a fresh session per command and has no continuously-open lifeline — so do not rely on "keep the session OPEN". Real recoverability per step, console-independent:
  - A1 firewall lockout → `fw-rollback` timer (300 s) → **recoverable without console.**
  - A2 SSH-config lockout → `ssh-revert` timer → **recoverable without console.**
  - A4 MTU → `netplan try` auto-revert (120 s) → **recoverable without console.**
  - A5 `rp_filter` → `rpf-revert` timer → **recoverable without console.**
  - **A8 reboot → a `systemd-run` timer does NOT survive a reboot.** This is the ONLY step whose failure is unrecoverable without an out-of-band console (bad MTU not persisted, firewall not persisted, broken upgrade → brick).
- **Console policy:** the provider web/serial console is the out-of-band fallback. It is a hard requirement **only for §A8 reboot**; for A1–A7/A9 the armed timers / `netplan try` make a console optional. **If no console exists (common on throwaway/test boxes):** A1–A7/A9 are safe to run when `systemd-run`/`netplan` are healthy; **A8 is the single gate** — proceed only with a working console OR explicit user acceptance of the risk of losing the box. Keep the current session open as a convenience, but never treat it as the safety net.
- **Idempotent.** Every block has `Skip-if`. Re-running the whole runbook after a partial failure must be safe. Never blindly append to shared configs — use dedicated drop-in files (see §Conventions).
- **Verify before proceeding. Never report a step "done" without showing the verify command's actual output.** A grep of a config file is NOT proof — verify *effective behavior* (`sshd -T`, `iptables -S`, a fresh login, a reachability test from the local machine).
- **Fail-safe is mandatory** for the firewall phase (§A1). Arm the timed rollback BEFORE the risky change; disarm only after a second session confirms access.
- **Reboot only when no rollback timer is armed.** The reboot is the LAST universal step (§A8). A reboot destroys any pending `systemd-run`/`at` rollback timer.
- **Execution context — every step runs in ONE of two places; the doc tags each:**
  - `[VPS]` — run inside the SSH session, on the server (all Apply blocks: iptables, apt, sysctl, sshd edits). Default if untagged.
  - `[LOCAL]` — run in YOUR controller shell, on your local machine. Used for genuine external reachability tests and second-session login checks. A reachability/second-session check run from inside the box loops back to itself and proves nothing — these MUST be `[LOCAL]`.
- **Lockout-capable vs forward-only blocks (governs abort):**
  - Lockout-capable: §A1 (firewall), §A2 (SSH), and two network steps that can sever connectivity — **A4 MTU netplan** (wrong MTU → black-holed packets; guard with `netplan try`'s 120 s auto-revert as the safety net) and **A5 `rp_filter=1`** (breaks asymmetric routing; on multi-uplink/policy-routed hosts use `2`, and verify a fresh `[LOCAL]` session after applying). Treat all four with the second-session-verify discipline.
  - Forward-only: §A3, §A6–§A9, and the non-lockout knobs of A4/A5 (everything EXCEPT the A4 MTU-netplan and A5 rp_filter steps called out above) cannot lock you out. A7 `apt purge` is **irreversible** (record the purged package list — see A7 — so the user can reinstall). There is nothing to "roll back" in these blocks.
- **Abort protocol (honest):** on failure in a lockout-capable block → run that block's defined rollback, restore the `iptables-save` backups, confirm SSH reachable from `[LOCAL]`, report state, do NOT continue. On failure in a forward-only block → STOP, report exact state to the user, do NOT continue to Phase B (no rollback attempt — record purged packages so the user can reinstall). On a **reboot that never reconnects (§A8)** → the box may be bricked and only the provider console can recover it; STOP and escalate to the user with console instructions — do NOT claim rollback is possible (you have no connection).
- **Cloud-provider firewall is invisible to the host.** Host `ACCEPT` ≠ reachability; an upstream security group can independently block or expose ports. Warn the user; never assume host rules == reachability.

### Controller prerequisites (the machine you drive FROM — resolve before §1)
- **Key auth is required before any SSH lockdown.** The runbook assumes `ssh -i <key> <host>`. If you were given **root + password only and no key** (common), note: the OpenSSH client cannot feed a password non-interactively, and `sshpass` is absent on Windows controllers. So the FIRST action is to create/upload a key (generate locally, push the pubkey to `authorized_keys`); until a key works, the `[LOCAL]` second-session verify cannot run unattended and §A2 (`PasswordAuthentication no`) must NOT be applied.
- **Password-only / Windows controller path:** use PuTTY `plink -pw <pass>` (or a paramiko wrapper, below) to bootstrap. `plink` in batch mode REJECTS an unknown host key (`Cannot confirm a host key in batch mode`) — pin it: `plink -hostkey SHA256:<fp> ...`. Note this PuTTY host-key cache lives in the registry (`HKCU\Software\SimonTatham\PuTTY\SshHostKeys`), NOT `known_hosts` — so the §A2 `ssh-keygen -R <host>` re-pin is an OpenSSH-only step; for `plink` you must update the registry/`-hostkey` fingerprint instead.
- **paramiko wrapper (recommended stateless executor):** a small paramiko script (`AutoAddPolicy`) gives clean rc/stdout/stderr, working stdin, and password auth on Windows. **Bonus:** with `AutoAddPolicy` a host-key change (e.g. after the §A2 host-key regeneration) is accepted automatically → no lockout. The big §A2 warning about `REMOTE HOST IDENTIFICATION HAS CHANGED` applies ONLY to an OpenSSH `known_hosts` / PuTTY-cache controller, NOT to a paramiko-`AutoAddPolicy` controller.
- **Executor handoff at §A2.** A password-based root executor (paramiko/`plink` with a password) STOPS WORKING the instant §A2 is applied — `PasswordAuthentication no` + `PermitRootLogin no` + `passwd -l root` together make a password+root session impossible (paramiko fails `BadAuthenticationType: allowed types: ['publickey']`). From that point the controller MUST run every remaining command (A3–A9) as `<admin-user>` over the key (`ssh -i <key> <admin-user>@<host> 'sudo …'`). Switch the executor from root+password to key+sudo BEFORE §A3.

### Conventions (apply everywhere)
- **sshd config:** drop-ins in `/etc/ssh/sshd_config.d/*.conf` only — NEVER edit `/etc/ssh/sshd_config` base. Drop-ins are read in **lexical order, first-obtained-value wins**. Number deliberately: `00-hardening.conf` beats stock `50-cloud-init.conf`. ALWAYS `sudo sshd -t` before any reload.
- **sysctl:** files in `/etc/sysctl.d/*.conf`, then `sudo sysctl --system`. Prefix `60-`/`99-` to win over distro defaults; mind files that sort *after* yours (`99-protect-links.conf`, `50-default.conf`).
- **Idempotency primitives:** drop-in files via `cat >` (the runbook OWNS those files); for shared/system files use anchored `grep -qE '^\s*KEY' file || echo ...`; `ipset ... -exist`; `iptables -C <rule> || iptables -A <rule>`.
- **Per-block format used below (most blocks; some use prose bullets):** `Detect` (current state) · `Skip-if` (idempotency) · `Apply` · `Verify → Expected` · `Rollback`. Where fields are not labeled, idempotency still holds via owned drop-in `cat >` overwrites and the `Skip-if`/detect notes inline.

---

## §0.5 — PRE-FLIGHT WORKLOAD DISCOVERY (run FIRST; classifies the box greenfield vs brownfield)

> The universal Phase A baseline assumes a FRESH box with no workload. Run this discovery pass BEFORE §1 to learn what the box ALREADY runs — **ANY** pre-installed workload (VPN of any kind, Docker/Podman containers, web server, reverse proxy, database, cache, mail, message queue, game server, control panel, monitoring agent, custom daemon, scheduled jobs) is SEVERED or degraded by the as-written firewall/forwarding/cleanup steps unless Phase A is adapted. Do not enumerate only the examples named here — discover whatever is actually present. This pass is **READ-ONLY (changes nothing)**. Delegate it to a dedicated recon sub-agent whose sole job is enumeration; keep its written inventory, not the raw dump.

- **Run every probe; write the result to `/root/vps-inventory.md`** (survives the A8 reboot — on disk, not session state). Nothing here mutates state.
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
  - **Greenfield** — ONLY `sshd` (+ systemd/DNS internals like `systemd-resolved` on 127.0.0.53) is listening, no Docker/VPN/container workload, `ip_forward=0`, firewall empty/default-ACCEPT. → Run Phase A EXACTLY as written.
  - **Brownfield** — ANYTHING beyond that baseline: any extra listening service (web, DB, cache, mail, queue, panel, game server, custom app), any container/VPN/tunnel, any `nat` rule, or `ip_forward=1`. → Do NOT run the universal Phase A blind. **STOP and present the inventory to the user**, then apply the adaptation matrix below; treat each detected workload as an already-installed Phase B module and secure AROUND it, never through it.

- **Brownfield adaptation matrix (how each block changes):**

  **§A1 firewall:**
  - **Classify each discovered LISTEN socket with the user — do NOT blanket-open everything:**
    - bound to `0.0.0.0`/`::` AND meant to be public (VPN port, 80/443, the app's port) → add an INPUT `ACCEPT` for it BEFORE `-P INPUT DROP`.
    - bound to `127.0.0.1`/`::1` (local-only) → leave it; the loopback ACCEPT already covers it, do NOT expose it.
    - publicly bound but SHOULD be private (DB/Redis/admin panel/metrics on `0.0.0.0` = a common misconfig) → do NOT open it to the world; flag it, and prefer binding it to localhost or restricting the source CIDR. Hardening means closing these, not preserving the exposure.
    - unknown/stale port with no owning service → surface to the user, don't auto-open.
  - Never SSH-only on a box that serves traffic, but never auto-expose a service that was never meant to be public either.
  - **Docker present → the raw fresh-build is FORBIDDEN.** Docker owns `DOCKER`/`DOCKER-USER`/`DOCKER-FORWARD` + the `nat` `MASQUERADE`; do NOT `iptables -F`/replace the ruleset. Insert INPUT rules WITHOUT flushing, leave Docker's chains intact, and put host rules that must affect container traffic in `DOCKER-USER` (not raw INPUT/FORWARD).
  - **Do NOT set `-P FORWARD DROP`** when any container/VPN/router forwarding exists — it black-holes the bridge and the tunnel. Snapshot and PRESERVE `iptables -t nat` (MASQUERADE/DNAT). `-P FORWARD DROP` is greenfield-only (`ip_forward=0`, no forwarding).

  **§A5 kernel:**
  - Forwarding workload (VPN/router/containers) → KEEP `ip_forward=1` and use `rp_filter=2` (loose), NOT `1` (strict drops asymmetric tunnel return paths). Keep ICMP type 3 code 4 (PMTUD) so the tunnel MTU works.

  **§A7 cleanup:**
  - `apt-mark manual` every package ANY detected service depends on (resolved from the LISTEN-socket → owning-package map above) BEFORE any `autoremove`/`purge --auto-remove`; never blind-purge. Skip the snapd purge if a snap-packaged workload exists; skip a purge whose `-s` dry-run would remove a package a running service needs.

  **§A8 reboot:**
  - Before reboot, confirm the workload's port(s) + forwarding + NAT are in the PERSISTED ruleset (same PRE-GATE discipline). After reboot, re-verify the workload is actually back (port listening, tunnel up), not just SSH.

---

## §1 — PRECONDITIONS (hard-gate; abort the relevant phase if unmet)

- **apt index refresh — HARD gate before ANY apt-install.** A freshly-reset box ships with an EMPTY `/var/lib/apt/lists/` (no `*Packages*` files) → the FIRST `apt-get install` in this runbook (§A1 `iptables-persistent`) fails `E: Package '...' has no installation candidate` (rc=100) → firewall never persists → §A8 reboot risk. The first `apt-get update` otherwise appears only in §A8 — far too late; this affects EVERY pre-A8 apt step (A1/A3/A6/A7). Run `sudo apt-get update` ONCE before any install (before §A1). Verify: `apt-cache policy iptables-persistent` shows a non-empty `Candidate`.
- **Connectivity tooling for the fail-safe:** all fail-safes in this runbook use `systemd-run` (always present). Verify: `command -v systemd-run` must succeed. Do NOT use `at`/`atd` — it is absent on minimal/cloud Ubuntu 24.04 and none of the disarm/verify commands here match it.
- **`[LOCAL]` second-session capability — HARD precondition for any fail-safe.** The entire firewall/SSH safety model depends on opening an INDEPENDENT new SSH session from your local controller within the timer window. Prove it works NOW: from `[LOCAL]`, open a throwaway session and run `ssh <host> true` — must succeed. If your execution environment cannot spawn a second independent connection, do NOT proceed to §A1/§A2. (A stateless one-shot executor spawns a fresh session per command — that satisfies this as long as each command-session is independent and key-auth works; see Controller prerequisites.)
- **Non-root sudo user — a working non-root sudo user with key auth MUST exist before any SSH lockdown (HARD gate).**
  - Detect: cloud-init images often pre-create `ubuntu` + injected key — check first (`getent passwd`, `ls /home/*/.ssh/authorized_keys`). **Warning:** a fresh VPS may have ONLY `root` as a shell user, an EMPTY `sudo` group, no `/home/*/.ssh`, and a `/root/.ssh/authorized_keys` that EXISTS but is EMPTY (0 lines). In that state key auth does not actually work yet — you must create the admin user AND install a working key FIRST. Applying §A2 (`PermitRootLogin no`, `PasswordAuthentication no`) before this = guaranteed lockout.
  - Apply (if absent): `adduser --disabled-password --gecos "" USER` — plain `adduser USER` is interactive (prompts `New password:` + gecos on stdin) → hangs/aborts (rc=124) under the stateless executor this runbook itself mandates; use `--disabled-password` (or `useradd -m -s /bin/bash USER`). Then `usermod -aG sudo USER`; install pubkey to `/home/USER/.ssh/authorized_keys`; `chmod 700 ~/.ssh && chmod 600 authorized_keys`, owned by USER (sshd silently ignores a key with loose perms/ownership).
  - **[soft] Set a password on the admin user** so the provider's web/VNC console works: `echo '<ADMIN_USER>:<STRONG_PASSWORD>' | sudo chpasswd` (substitute a strong password provided by or agreed with the user — NEVER a weak or literal default). This password is ONLY for console/emergency access; SSH still uses key auth. Also keep the NOPASSWD-sudoers drop-in — the password is a console login fallback, not a sudo gate.
  - **Verify in a SEPARATE, still-open session:** key login AND `sudo -n true` (or `sudo whoami`) both succeed. Do NOT use `sudo -v` for this gate — it requires a tty and fails from a non-interactive `[LOCAL]` session (`sudo: A terminal is required to authenticate`) even WITH NOPASSWD, while `sudo whoami` works; `sudo -n true` is the correct no-tty gate. Since the admin user is created passwordless (`--disabled-password`), a non-interactive executor needs a NOPASSWD-sudoers drop-in (e.g. `/etc/sudoers.d/90-USER`: `USER ALL=(ALL) NOPASSWD:ALL`) for `sudo` to succeed without a tty. Only then is `PermitRootLogin no` / `PasswordAuthentication no` safe.
- **Hardening mode — ask BEFORE Phase A (HARD gate for §A2).** Ask the user: strict or soft? Persist to `/root/vps-workload.conf` as `HARDENING_MODE=strict|soft`. **Strict** = maximum security (root password locked, `PermitRootLogin no`, no console password fallback). **Soft** = same SSH hardening but admin user and root keep a working password for the provider's web/VNC console — safety net if SSH key is lost. **Default if no answer or user unsure: `soft`.** This MUST be resolved before §A2 runs — it determines the `PermitRootLogin` value and whether `passwd -l root` executes. The remaining interview questions (workload, ports, traffic profile) stay in §I and can run in parallel with A1–A7 as before.
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

- **SSH connection family** (drives v4/v6 firewall): `CLIENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')`. A `:` (including IPv4-mapped `::ffff:a.b.c.d`) ⇒ treat as IPv6 path. (`SSH_CONNECTION` is set only inside the sshd session — not under cron/systemd.)
- **Egress interface — derive from the DEFAULT ROUTE, not the client IP.**
  - `ip -4 route get 1.1.1.1` and `ip -6 route get 2606:4700:4700::1111`; take the token after `dev`. **Abort if empty or `lo`.**
  - If v4/v6 egress differ, or multiple non-loopback default/ECMP NICs exist (multi-NIC, bonded, policy-routed) → do NOT auto-pick; abort and require the operator to name the interface. (Client-IP routing can pick a non-egress NIC under asymmetric routing and still pass a non-empty check → lockout.)
- **Existing firewall owner (judge the FIREWALL, not the unit):** `ufw status` (NOT `systemctl is-active ufw`) is the truth for whether the firewall is enforcing. The `ufw.service` unit can report `active` (loaded) while `ufw status` is `inactive` and iptables are empty default-ACCEPT — the unit being loaded does NOT mean the firewall is on. Run `ufw status verbose; systemctl is-active firewalld nftables; iptables -S; nft list ruleset` and decide the owner from `ufw status` / actual rules. Commit to ONE owner (see §A1 firewall-owner detection).
- **Resources / inventory:** RAM & disk (`free -m`, `df -h`, `lsblk`), installed packages (drives §A7 cleanup skip-ifs), `/boot` free space (≥1 GB for kernel upgrades).

### Placeholder → source (resolve ALL before first use; never write a literal `<...>` into a config)
| Placeholder | How to obtain | Used in |
|---|---|---|
| `<host>` | the VPS address/alias your controller uses to SSH in | all `[LOCAL]` commands |
| `<key>` | the private-key path your controller authenticates with | `[LOCAL]` login verifies |
| `<admin-user>` | the verified non-root sudo user from the §1 non-root sudo user step | A2 `AllowUsers` |
| `CLIENT_IP` / `<ADMIN_IP_OR_CIDR>` | `echo "$SSH_CONNECTION" \| awk '{print $1}'` (your controller's IP) | A3 `ignoreip` |
| `<iface>` | egress NIC from §2 default-route detect | A4 netplan, firewall |
| `<MAC>` | `cat /sys/class/net/<iface>/address` (or `ip link show <iface>`) | A4 netplan match |
| `<SERVER_PUBLIC_IPV4>` / `_IPV6` | `ip -4 addr show <iface>` / `ip -6 ...`; if the public IP is NAT'd and not on the NIC, query the provider metadata or `curl -s https://api.ipify.org` (note: do this BEFORE any egress-blocking firewall) | A3 `ignoreip` |
| `<RELAY_IP>` | provided by the user in the interview (§I) for the RF module | B RF blocklist whitelist |
| `<remote>` / `<peer>` / `<large-file-url>` | optional diagnostic targets; default-skip if none (§A4 speed-test, MTU) | A4 (optional) |

> If any required placeholder cannot be resolved, STOP and ask the user — do NOT guess and do NOT leave the literal token in a file (e.g. `AllowUsers <admin-user>` = nobody can log in = lockout).

---

# PHASE A — UNIVERSAL BASELINE (always; no questions)

Run **§0.5 pre-flight discovery FIRST** — on a brownfield box (existing VPN/Docker/web/DB) apply its adaptation matrix, do NOT run the blocks below blind.
Apply order is load-bearing: **A1 firewall (close inbound holes first) → A2 SSH crypto → A3 fail2ban → A4 network → A5 kernel → A6 maintenance → A7 cleanup → A8 full-upgrade + reboot (LAST) → A9 unattended-upgrades.**
Run the **Interview (§I)** in parallel with A1–A7 (it is an agent↔user conversation, not on the box). Do NOT start Phase B until both Phase A is fully verified (incl. post-reboot re-SSH) AND interview answers are collected.

## A1 — Firewall + fail-safe (iptables-nft; mirror ALL rules into ip6tables)

- **Firewall owner — establish a single owner BEFORE touching rules.** Decide by `ufw status`, not `systemctl is-active ufw`: the unit can be `active`/loaded while `ufw status` = `inactive` (firewall OFF, iptables empty default-ACCEPT). If `ufw status` = **active** → use `ufw allow OpenSSH` / `ufw allow 22/tcp` and do NOT add raw rules (a UFW reload flushes out-of-band rules → SSH lockout). If you choose raw iptables (the fresh-box case) → `sudo ufw --force disable` first (expected output: "Firewall stopped and disabled on system startup"), then commit raw rules. SSH ACCEPT must exist before any `enable`/reload.
- **nft backend — `iptables` is the iptables-nft shim** (`iptables --version` → `(nf_tables)`). Pick ONE backend host-wide; never mix native `nft` on tables iptables-nft owns; do NOT switch to iptables-legacy; never `nft flush ruleset`.
- **Fail-safe (systemd-run) — ARM BEFORE the risky change:**
  - First snapshot: `iptables-save > /root/iptables-backup.v4 ; ip6tables-save > /root/iptables-backup.v6`.
  - Write `/usr/local/sbin/fw-rollback.sh` (idempotent; see the rollback-script block below), `chmod +x`.
  - Arm: `sudo systemd-run --on-active=300 --unit=fw-rollback /usr/local/sbin/fw-rollback.sh` (fires in 5 min).
  - **The 300 s is a HARD deadline.** Apply the firewall, then IMMEDIATELY do the `[LOCAL]` second-session verify and disarm — all within the window. If you cannot finish in time, RE-ARM before expiry — but you must clear the old unit first or `systemd-run` errors with "unit already exists" and the original timer still fires: `sudo systemctl stop fw-rollback.timer; sudo systemctl reset-failed 'fw-rollback.*'` THEN re-issue `systemd-run --on-active=600 --unit=fw-rollback ...` (or use a fresh `--unit` name). Raise `--on-active` if your verify is genuinely slow.
  - After verifying access from a second `[LOCAL]` session: **disarm the TIMER** — `sudo systemctl stop fw-rollback.timer && sudo systemctl reset-failed fw-rollback.timer fw-rollback.service 2>/dev/null || true`. (Stopping the `.service` does NOT cancel a pending one-shot — stop the timer.) After `stop`, the `systemd-run` transient unit DISAPPEARS, so `reset-failed` prints `Failed to reset failed state ...: Unit not loaded` — harmless (the timer is already gone; confirm via `list-timers | grep fw-rollback` = empty), but a literal agent may misread it as a failed disarm; the `2>/dev/null || true` suppresses it.
- **Rollback script** — `/usr/local/sbin/fw-rollback.sh` (open policies BEFORE flush, then restore backup):
  ```sh
  #!/bin/sh
  iptables  -P INPUT ACCEPT; iptables  -P FORWARD ACCEPT; iptables  -P OUTPUT ACCEPT
  ip6tables -P INPUT ACCEPT; ip6tables -P FORWARD ACCEPT; ip6tables -P OUTPUT ACCEPT
  iptables -F; iptables -X; ip6tables -F; ip6tables -X
  iptables-restore  < /root/iptables-backup.v4
  ip6tables-restore < /root/iptables-backup.v6
  systemctl restart ssh.socket 2>/dev/null || systemctl reload ssh 2>/dev/null || true
  ```
  (`iptables -F` alone is insufficient — it does not reset chain policy. Use `restart ssh.socket` since the listener is socket-owned on 24.04/26.04.)
  - **Deliver this script with `printf`, not a stdin heredoc, under a stateless one-shot controller.** When the whole command is piped through SSH (`ssh ... "base64 -d | sudo bash"` or `... <<'EOF'`), a `cat <<'EOF' > file` here-doc competes for the same stdin and truncates/corrupts the file. Write it with `printf '%s\n' '#!/bin/sh' 'iptables -P INPUT ACCEPT' ... > /usr/local/sbin/fw-rollback.sh` (or base64-decode a single argument), which is stdin-safe. Same caveat applies anywhere this runbook shows a `cat <<'EOF'`.
  - **Port-change interaction (A1↔A2):** the snapshot above only contains the SSH port open at A1 time (22). If A2 later changes the SSH port, this rollback would restore a ruleset that blocks the NEW port = self-lockout. Therefore: change the SSH port ONLY after the A1 fail-safe is disarmed, then re-run BOTH `iptables-save > /root/iptables-backup.v4` (+ `ip6tables-save > ...v6`) AND `sudo netfilter-persistent save` so the fail-safe backup and the boot ruleset both match the new port.
- **Choose build path from §2 detect:** if `iptables -S` shows an empty/default-ACCEPT chain (the expected fresh-VPS case) → use the fresh deterministic build below. If it already shows non-trivial rules or a DROP policy (a brownfield box — VPN/Docker/router; cross-check the §0.5 inventory) → this runbook does NOT auto-merge an unknown ruleset: insert the SSH ACCEPT ahead of any existing DROP immediately (`iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT`) to protect the session, then **STOP and ask the user** how to proceed (adopt / replace the existing firewall). Do NOT guess a merge, do NOT `iptables -F`, and follow the §0.5 brownfield adaptation matrix (preserve Docker/NAT chains, open workload ports, no `-P FORWARD DROP`).
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
  ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP            # mirror the v4 INVALID drop
  ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 1 -j ACCEPT   # repeat for 2,3,4,133,134,135,136
  ip6tables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
  ip6tables -P INPUT DROP
  ip6tables -P FORWARD DROP                                            # mirror v4 FORWARD DROP
  ```
  - The v6 mirror MUST include the `INVALID -j DROP` (placed after loopback, before ESTABLISHED,RELATED) and `-P FORWARD DROP` so v6 matches v4. ICMPv6 types 1,2,3,4,133–136 stay ACCEPT (NDP/PMTUD). A global IPv6 (e.g. a `/48` on the NIC) makes this mirror mandatory, not optional.
- **Persistence** — `sudo apt-get install -y iptables-persistent` (pulls netfilter-persistent; restores `/etc/iptables/rules.v{4,6}` at boot). This is the FIRST apt-install in the runbook — it REQUIRES a prior `sudo apt-get update` (see §1 apt-index refresh gate). On a freshly-reset box the apt index is empty, so without the update this fails `E: Package 'iptables-persistent' has no installation candidate` (rc=100) and the firewall never persists. Confirm `apt-cache policy iptables-persistent` shows a non-empty `Candidate` before installing. The debconf save prompt is interactive and will HANG a non-interactive agent — **preseed it to DECLINE auto-save** before installing:
  ```sh
  echo 'iptables-persistent iptables-persistent/autosave_v4 boolean false' | sudo debconf-set-selections
  echo 'iptables-persistent iptables-persistent/autosave_v6 boolean false' | sudo debconf-set-selections
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
  ```
  (Declining auto-save is correct here — the firewall isn't finalized yet.) Persist ONLY after a second session confirms no lockout: `sudo netfilter-persistent save`.
  - **needrestart stderr is noise, not failure:** on 26.04 `apt-get install` emits needrestart kernel/service-check chatter to stderr. Do not treat non-empty stderr as an error — check the exit code.
  - **Phase A makes NO `iptables`/`ip6tables` changes after this save — EXCEPT if the SSH port is changed in A2**, in which case you MUST re-run `sudo netfilter-persistent save` after opening the new port (otherwise `/etc/iptables/rules.v4` still allows only `:22` and the A8 reboot locks you out on the new port with no armed timer). Otherwise no re-save needed before A8. fail2ban (A3) adds its OWN nft table that is NOT in `rules.v{4,6}` and is regenerated by the service at boot — expected; do not try to reconcile it into the saved set. Post-reboot, verify the firewall against the persisted file (`diff <(iptables-save) /etc/iptables/rules.v4` ignoring fail2ban's `f2b-*` chains), not by eyeballing raw `iptables -S`.
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
  LoginGraceTime 30                  # do NOT set 0 (MaxStartups DoS); 9.6p1+ (incl. 10.2p1) patches CVE-2024-6387
  AllowUsers <admin-user>            # whitelist; confirm this user has working key first

  # [26.04] mlkem768x25519-sha256 is the post-quantum DEFAULT in OpenSSH 10.x — list it FIRST.
  # On 9.6p1 (24.04) it does not exist; drop the first token there. sntrup761x25519-sha512 has NO @suffix on 10.x.
  KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
  HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  RequiredRSASize 3072
  ```
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
  awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe && mv /etc/ssh/moduli.safe /etc/ssh/moduli
  systemctl restart ssh
  ```
  - **Full-regen path (only if the existing keys are weak/missing — e.g. RSA <3072 or no ed25519):** as root:
  ```
  rm /etc/ssh/ssh_host_*
  ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
  ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
  awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe && mv /etc/ssh/moduli.safe /etc/ssh/moduli
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
     - **[soft] Do NOT lock the root password and do NOT set `PermitRootLogin no`.** Instead:
       - Set `PermitRootLogin prohibit-password` in `99-hardening.conf` (root can't SSH with a password, but CAN log in via the provider console).
       - Keep the root password as-is (do NOT run `passwd -l root`). The user can access the server via the provider's web/VNC console → log in as root or the admin user with their password → recover from a lost SSH key.
       - Optionally set a STRONG root password if one isn't set: `echo 'root:<STRONG_PASSWORD>' | sudo chpasswd` — coordinate with the user.
       - **Security trade-off (document for user):** soft mode leaves a local-TTY password surface (console only, NOT SSH-reachable). An attacker with physical/console access to the VM could brute-force the password — but on a VPS, console access = provider access = game over anyway. The real risk is a weak password; enforce a strong one.
  - **Port / ListenAddress** (only if changing the port — socket-activated on 24.04): open the new port in the firewall FIRST AND re-snapshot the A1 fail-safe backup (per §A1 persistence), then `sudo sshd -t && sudo systemctl daemon-reload && sudo systemctl restart ssh.socket` (`reload ssh` will NOT move the listener).
- **Verify → Expected:** `sudo sshd -t` exits 0; `sudo sshd -T | grep -Ei 'passwordauthentication|kbdinteractiveauthentication|permitrootlogin|maxauthtries'` shows the hardened values; a NEW key-only `[LOCAL]` session logs in BEFORE you close the current one — use `ssh -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -i <key> <admin-user>@<host> true` (`IdentitiesOnly` is REQUIRED — without it an agent with >3 loaded keys exhausts `MaxAuthTries 3` and the verify falsely fails). Optional: `ssh-audit <host>` clean.
- **A2 has no firewall-style auto-rollback — the open session is the SOLE safety net.** A drop-in can pass `sshd -t` yet still bar login (e.g. wrong `AllowUsers`). For extra safety, arm a revert timer before reload: `sudo systemd-run --on-active=300 --unit=ssh-revert sh -c 'rm /etc/ssh/sshd_config.d/00-hardening.conf /etc/ssh/sshd_config.d/99-hardening.conf; systemctl reload ssh'`, then cancel it (`systemctl stop ssh-revert.timer`) only after a fresh `[LOCAL]` login succeeds.
- **Rollback:** keep the prior drop-in content; on `sshd -t` failure do NOT reload — fix or remove the drop-in.

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
  - **don't rely on `ignoreself` alone** — it only covers the host's primary DNS IP + loopback (upstream #3132), not secondary public IPs. The load-bearing part is the explicit static admin IP. A dynamic admin IP = false safety → keep console fallback.
  - **banaction:** leave the default `nftables`. Do NOT set obsolete `iptables-multiport` (creates a conflicting `ip filter` table). Override files must sort AFTER `defaults-debian.conf`. (fail2ban's `nftables` action uses its OWN dedicated table — this does NOT violate the §A1 "single backend / don't mix native nft" rule, which is about the table iptables-nft owns.)
- **Apply / Verify → Expected:** `systemctl restart fail2ban`; `fail2ban-client status sshd` active; `journalctl -u fail2ban` shows no backend errors. (`fail2ban-client get sshd ignoreip` lists the explicit IPs only — self-IPs from `ignoreself` won't appear; that's expected.)

## A4 — Network tuning (`/etc/sysctl.d/`; performance, not security unless noted)

> **Decision rule — do NOT agent-judge "only if…" conditions.** Every knob below marked *context-dependent* / *module-only* / *raise only for X* is **SKIPPED in universal Phase A** and applied ONLY if a *collected* interview answer (§I, in `/root/vps-workload.conf`) explicitly calls for it (long-fat-network → 64 MiB buffers; high-connection/NAT → conntrack-max; relay/outbound-heavy → tcp_tw_reuse=1; provider known to clip MTU → MTU detect). No answer at the time A4 runs ⇒ keep the universal default, skip the optional block. Never stall waiting; never guess the condition.

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
- **Speed test — optional diagnostic only.** Prefer `curl -o /dev/null -s -w 'down=%{speed_download} B/s\n' https://<large-file-url>` (×8 = bits/s) or `iperf3 -c <peer> -J`. Do NOT invoke the Ookla Speedtest CLI interactively (first-run EULA hangs an unattended agent); if required: `speedtest --accept-license --accept-gdpr -f json`.

## A5 — Kernel hardening (`/etc/sysctl.d/99-zz-kernel-harden.conf` — the `zz` prefix sorts AFTER distro `99-protect-links.conf`/`50-default.conf`, else `fs.protected_*` / redirects are silently re-overridden)

```
# Info-leak / process protections
kernel.kptr_restrict = 2           # use 1 if you profile with perf/eBPF kernel symbols
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1       # do NOT use 3 (irreversible, breaks debuggers)
kernel.randomize_va_space = 2
fs.suid_dumpable = 0               # also set `* hard core 0` + coredump.conf for full effect
kernel.unprivileged_bpf_disabled = 1   # one-way until reboot; use 2 if unprivileged-BPF tooling runs
net.core.bpf_jit_harden = 2
# Link protections (raise fifos to 2 optional; do NOT lower regular below 2)
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
- **`rp_filter=1` is lockout-capable (can sever an asymmetric-routed session) and A5 has NO auto-rollback — the open session is the sole net (as in A2).** Before applying, snapshot is not enough: arm a revert timer `sudo systemd-run --on-active=300 --unit=rpf-revert sh -c "sed -i 's/rp_filter = 1/rp_filter = 2/' /etc/sysctl.d/99-zz-kernel-harden.conf; sysctl --system"`, apply, then do a fresh `[LOCAL]` session check; cancel the timer (`systemctl stop rpf-revert.timer`) only after it succeeds.
- **Decision rule (do NOT agent-judge):** universal default = `1`. Use `2` (loose) ONLY if a collected interview answer says the host is multi-uplink/BGP/policy-routed/VPN. No answer ⇒ keep `1`; never infer from topology.
- **kexec lockdown — context-dependent, NOT universal:** `kernel.kexec_load_disabled = 1` only on hosts WITHOUT kdump/Livepatch (one-way until reboot; breaks crash-dump capture).
- **IP forwarding:** universal leaves `net.ipv4.ip_forward = 0` (do NOT set). VPN/relay module only sets `=1` — and **ip_forward toggling RESETS all other IPv4 conf params to defaults**, so in that module set `ip_forward` FIRST, then re-apply rp_filter/redirects.

## A6 — System maintenance

- **journald cap** `/etc/systemd/journald.conf.d/99-vps-cap.conf` (journald is the primary log on minimal — no rsyslog):
  ```
  [Journal]
  SystemMaxUse=500M
  SystemKeepFree=1G
  MaxRetentionSec=2week
  ```
  Ensure persistence first (`sudo mkdir -p /var/log/journal`), then `sudo systemctl restart systemd-journald`. (System* caps are no-ops on a volatile journal.)
- **needrestart non-interactive** (auto-restart services; does not auto-reboot for kernels; needs needrestart ≥ 3.6-7ubuntu4.1) — use a single-quoted heredoc so `$nrconf` is written literally:
  ```
  sudo tee /etc/needrestart/conf.d/50-autorestart.conf >/dev/null <<'EOF'
  $nrconf{restart} = 'a';
  EOF
  ```
- **time sync:** `timedatectl status` → "System clock synchronized: yes" / "NTP service: active"; if off `sudo timedatectl set-ntp true`. If chrony installed, disable timesyncd (never both).
- **AppArmor:** verify, do not disable — `sudo aa-status` shows profiles loaded/enforce. No `apparmor=0` in GRUB; don't mask the service.

## A7 — Cleanup (headless/virtualized; ALWAYS dry-run before purge)

> **Purges are irreversible — log them so the user can reinstall.** Before each purge, append the resolved package set to `/root/vps-purged-packages.log`. `apt-get -s purge` prints `Purg <pkg>` lines (and `Remv <pkg>` for plain removals), so the old `awk '/^Remv/{print $2}'` matches NOTHING on a purge → an EMPTY log → the user can't tell what to reinstall. Match both, or read the fact from `dpkg.log`:
> ```sh
> # capture the SIMULATED set before purging:
> apt-get -s purge <pkgs> | awk '/^(Remv|Purg)/{print $2}' >> /root/vps-purged-packages.log
> # OR (more reliable) capture what ACTUALLY happened, after the purge:
> grep -E " (remove|purge) " /var/log/dpkg.log | awk '{print $4}' >> /root/vps-purged-packages.log
> ```
> This is mandatory on the normal path, not just on failure.

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
- `sudo apt-get purge -y sysstat`. To keep tools, set `ENABLED="false"` in `/etc/default/sysstat` + disable the timers (on 24.04 the collect timer runs despite ENABLED=false — LP #2066117, confirm stopped).
- **Autoremove safety — guard cloud-init/kernel:** `sudo apt-mark hold cloud-init netplan.io` FIRST (autoremove can pull `netplan.io` via cloud-init → no network on reboot). Dry-run `sudo apt-get -s autoremove --purge`, inspect the Remv/Purg list, match against `uname -r` (a manually-booted old kernel can be removed). Only then run for real.
  - **[26.04] `--auto-remove` cascades WIDE — review the dry-run, it removes more than you target.** On 26.04 the packagekit/apport purges + autoremove can pull in: `ubuntu-server` (metapackage), `jq`, `software-properties-common` (⇒ no more `add-apt-repository`), `appstream`, `modemmanager`/`libqmi`/`libmbim`, and `ufw`. If you need any of these, `sudo apt-mark manual <pkg>` BEFORE the purge (or reinstall after, from the log). Always read the simulated set first; never blind-run `purge --auto-remove`.
- **[OPTIONAL] snapd:** snapd is not purged on the universal baseline; on a minimal headless VPS it's usually dead weight (the `snapd` daemon + `snap-repair.timer`). If no workload needs snaps: `sudo systemctl disable --now snapd.socket snapd.service snap.seeded.service 2>/dev/null; sudo apt-get purge -y snapd && sudo apt-get autoremove -y` (log purged set per the top note). Skip if snaps are in use.
- `sudo apt-get clean` and `sudo journalctl --vacuum-size=200M` (the suffix is REQUIRED — bare `--vacuum-size` errors).
- **Reset failed units — clear stale failed units after purge.** Purging a service (e.g. `apport.service`, `multipathd-queueing.service`) leaves it in `systemctl --failed` as `not-found`, which makes the §V "no new failed units" check FALSE-fail. After purges run: `sudo systemctl reset-failed` (or target specific units: `sudo systemctl reset-failed apport.service multipathd-queueing.service`). Then re-check `systemctl --failed` is clean.

## A8 — Full upgrade + reboot (LAST universal step; only when no rollback timer is armed)

- **PRE-GATE (must all hold before rebooting):** no `fw-rollback`/`ssh-revert` timer armed (`systemctl list-timers` clean); firewall already persisted (`sudo netfilter-persistent save` succeeded in A1 — verify `/etc/iptables/rules.v4` + `rules.v6` exist and are non-empty), else the box can boot default-ACCEPT/empty = silently unhardened. `rules.v{4,6}` are `0640 root:root` — read them WITH `sudo` (e.g. `sudo wc -l /etc/iptables/rules.v4 /etc/iptables/rules.v6`); since the executor is now the non-root admin user, a bare `wc -l`/`cat` returns `Permission denied` (0 lines) and a literal agent may wrongly conclude the firewall is not persisted.
- **Full upgrade:**
  ```
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  apt-get update
  apt-get full-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
  ```
  `--force-confold` keeps YOUR hardening edits (reconcile any `*.dpkg-dist` later). `full-upgrade` MAY remove packages — review the list.
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
- **Post-reboot re-verification pass (run BEFORE enabling A9)** — confirm the upgrade/`--force-confold`/module-load races didn't drop hardening: `sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|macs'` (hardened); key sysctls effective (`sysctl net.ipv4.tcp_congestion_control kernel.kptr_restrict fs.protected_regular net.ipv4.conf.all.rp_filter`); `fail2ban-client status sshd` active; firewall matches the persisted file (per §A1 persistence). Re-apply any control that regressed before A9.

## A9 — Unattended security updates (enable LAST, after reboot verified)

- `/etc/apt/apt.conf.d/20auto-upgrades`:
  ```
  APT::Periodic::Update-Package-Lists "1";
  APT::Periodic::Unattended-Upgrade "1";
  APT::Periodic::AutocleanInterval "7";
  ```
- **do NOT overwrite `/etc/apt/apt.conf.d/50unattended-upgrades` — use a separate drop-in.** The package-shipped `50unattended-upgrades` contains `Unattended-Upgrade::Allowed-Origins` (the security patterns, e.g. `o=Ubuntu,a=${distro_codename}-security`). Replacing that file with just the three override lines SILENTLY KILLS Allowed-Origins → unattended-upgrades then installs nothing. apt reads every file in `apt.conf.d/` and the later (higher-numbered) file wins for a given key, so put the overrides in their own file and leave `50-` untouched. Write `/etc/apt/apt.conf.d/52-unattended-upgrades-local`:
  ```
  Unattended-Upgrade::Automatic-Reboot "false";          # agent controls reboots
  Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
  Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
  ```
  Requires `apt-get install -y unattended-upgrades`. Because auto-reboot is off, the agent (or operator) MUST watch `/var/run/reboot-required` and schedule reboots, or kernel/libc/openssl fixes stay inactive.
- **Verify → Expected:** `unattended-upgrade --dry-run --debug` shows the security origin enabled AND `Allowed-Origins` listed. **[26.04]** the codename is `resolute`, so the dry-run shows e.g. `Allowed origins: o=Ubuntu,a=resolute-security,...`. Any codename-hardcode in a config (there should be none — patterns use `${distro_codename}`) must match the running release.

---

# §I — INTERVIEW (run in parallel with A1–A7; agent↔user, off-box)

**Interleave** the interview between A-block steps (a single agent can't truly run a conversation concurrently with commands — ask questions in the gaps between/after Apply blocks, never block Phase A waiting on an answer). Persist answers to `/root/vps-workload.conf` on the box (survives the A8 reboot — it's on disk, not session state). **Concrete absent-user gate:** if no workload answer has been given by the time Phase A is fully verified, proceed as **B-none** — do NOT block, do NOT guess a workload.

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
- **ICMP — never blanket-DROP ICMP/ICMPv6.** IPv4 PMTUD = ICMP **type 3 code 4** (frag-needed). Keep ESTABLISHED,RELATED ACCEPT before any ICMP DROP. Allow IPv4 frag-needed/echo-reply/time-exceeded; IPv6 packet-too-big(2)/time-exceeded/destination-unreachable + NDP 133–137. Add `-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`. (Dropping IPv6 type 2 = total failure past a smaller-MTU hop — routers never fragment.)
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
  Refresh daily via systemd timer. Fail HARD on MD5 mismatch (never swap a partial set). **Re-assert the whitelist every load** — guards against a future list revision that contains your own relay/management IP.
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

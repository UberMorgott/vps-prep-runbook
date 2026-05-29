# VPS-PREP-RUNBOOK — ADDENDUM (detection, egress, OS-hardening, fixes)

Drop-in companion to `VPS-PREP-RUNBOOK.md`. Same conventions, same `[VPS]`/`[LOCAL]`, `strict|soft`, `[26.04]` tagging. Same per-block format (`Detect` · `Skip-if` · `Apply` · `Verify → Expected` · `Rollback`). This addendum closes gaps in the base runbook: it is strong on **lockout-avoidance and closing inbound**, but near-empty on **post-compromise detection and egress containment**. Items below slot into Phase A or run as optional strict-only modules. Nothing here is required for a working greenfield bring-up except the **§1-FIX / §A2-FIX corrections**, which supersede the matching base-runbook steps.

---

## §1-FIX — Set the console password WITHOUT leaking it (supersedes the `chpasswd` lines in §1 [soft] and §A2 [soft])

The base runbook sets the admin/root console password with `echo '<user>:<PW>' | sudo chpasswd`. Under the **stateless one-shot executor this runbook itself mandates**, the controller wraps each command as `ssh <host> 'sudo bash -c "…"'` — so the plaintext password ends up (a) in the remote shell's process args, briefly visible in `ps`, (b) in the **controller's own transcript/logs**, and (c) in shell history if interactive. That directly violates the launch-prompt contract **"never log my password."** (Note: a bare interactive `echo … | chpasswd` does NOT leak via `ps` because `echo` is a builtin — but the `bash -c "…"` wrapper and the controller transcript do leak it.)

- **Skip-if:** `strict` mode (no console password is set at all) — not applicable.
- **Apply — generate the password ON THE BOX so plaintext never crosses the wire:**
  ```
  set +o history
  ADMIN_PW="$(openssl rand -base64 18)"
  printf '%s:%s\n' "<admin-user>" "$ADMIN_PW" | sudo chpasswd
  printf 'CONSOLE PASSWORD (store now, shown once): %s\n' "$ADMIN_PW"
  unset ADMIN_PW
  ```
  Because `"$ADMIN_PW"` is expanded **inside the remote shell** (a variable assigned from `openssl` output, not a literal in the command string), the plaintext is never in the `bash -c` argument the controller sends — so it is not in the controller transcript. The only exposure is the deliberate one-time surfacing to the user.
- **Agent contract addendum:** the one-time-surfacing line is the SOLE place the password appears. The agent MUST treat it as secret: do not repeat, persist, or include it in any summary. If your executor logs all stdout, redact this line.
- **Verify → Expected:** `sudo passwd -S <admin-user>` shows `P`; a provider-console login with the surfaced password succeeds; the password appears in NO on-box file, NO history, NO controller log.
- **Rollback:** `sudo passwd -l <admin-user>` if the user opts back into strict.

---

## §A2-FIX — Use `AllowGroups`, not `AllowUsers <single-user>` (refines §A2 `99-hardening.conf`)

`AllowUsers <admin-user>` works but is brittle: every added operator means editing sshd config and reloading (a lockout-capable action). A group is the maintainable form.

- **Skip-if:** group `sshusers` exists AND contains the admin user AND `99-hardening.conf` already uses `AllowGroups sshusers`.
- **Apply:**
  ```
  sudo groupadd -f sshusers
  sudo usermod -aG sshusers <admin-user>
  # in /etc/ssh/sshd_config.d/99-hardening.conf, replace `AllowUsers <admin-user>` with `AllowGroups sshusers`
  sudo sshd -t && sudo systemctl reload ssh
  ```
- **Verify → Expected:** `id <admin-user>` lists `sshusers`; `sudo sshd -T | grep -i allowgroups` shows `allowgroups sshusers`; a fresh `[LOCAL]` key login as `<admin-user>` still succeeds (verify in a second session before closing the current one — lockout-capable, same discipline as §A2).
- **Rollback:** keep the prior `AllowUsers` drop-in; on `sshd -t` failure do not reload.

---

## §A2.5 — Neutralize cloud-init so it can't undo your hardening on reboot (new; after §A2, before §A8)

The base runbook only `apt-mark hold`s `cloud-init`/`netplan.io`. The **service** still runs on boot, and on several providers cloud-init re-applies netplan (overwriting the §A4 MTU drop-in) and re-asserts users/SSH every boot — so the **§A8 reboot can silently revert parts of A2/A4.** A `hold` prevents removal, not re-execution.

- **Detect:** `cloud-init status 2>/dev/null`; `ls /etc/cloud/cloud.cfg.d/`; confirm whether the provider uses cloud-init first-boot-only (typical) vs every-boot network config (some).
- **Skip-if:** `cloud-init` not installed (`[26.04]` may ship only a leftover `50-cloud-init.conf`), OR the provider needs cloud-init every boot for networking (then DON'T disable; make your netplan drop-in win instead).
- **Apply (only after provisioning is complete and network is persisted via netplan):**
  ```
  sudo touch /etc/cloud/cloud-init.disabled
  ```
- **Verify → Expected:** after the §A8 reboot, `cloud-init status` reports disabled and §A4 MTU / §A2 SSH settings are unchanged.
- **Rollback:** `sudo rm /etc/cloud/cloud-init.disabled`.

---

## §A6.5 — DNS hardening on systemd-resolved (new; extends §A6)

Minimal Ubuntu uses `systemd-resolved` on `127.0.0.53` with no DNSSEC validation and cleartext DNS.

- **Skip-if:** a different resolver is in use, or the drop-in already exists with these values.
- **Apply:** write `/etc/systemd/resolved.conf.d/99-dns-hardening.conf`:
  ```
  [Resolve]
  DNSSEC=allow-downgrade
  DNSOverTLS=opportunistic
  ```
  then `sudo systemctl restart systemd-resolved`. (`allow-downgrade`/`opportunistic`, not `yes` — strict `yes` breaks on captive portals and resolvers without DoT. Raise to `yes` only when you control the upstream resolver.)
- **Verify → Expected:** `resolvectl status` shows the values on the link; `resolvectl query example.com` still resolves.
- **Rollback:** remove the drop-in, restart `systemd-resolved`.

---

## §A10 — DETECTION & MONITORING (new universal block; after §A3, parallel-safe)

The base runbook's only detective control is fail2ban (reacts to *failed* auth only). Nothing watches for a *successful* intrusion, config tampering, or privilege escalation, and there's no forensic trail.

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
  (Per the base-runbook stdin caveat under a stateless executor: deliver the rules file via base64 → `base64 -d | sudo tee …`, not a piped heredoc, if your controller pipes stdin.)
- **Verify → Expected:** `sudo auditctl -l` lists the rules; `sudo ausearch -k sshd_config` returns events after touching a watched file.
- **Rollback:** `sudo rm /etc/audit/rules.d/99-vps.rules && sudo augenrules --load`.

### A10.2 — Successful-login notification (PAM)
- **Skip-if:** `/usr/local/sbin/ssh-login-notify.sh` exists and the `pam_exec` line is in `/etc/pam.d/sshd`.
- **Apply:**
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
- **Apply:** `sudo apt-get install -y aide aide-common`; `sudo aideinit`; `sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db`; rely on the packaged `dailyaidecheck.timer`. **Initialize the baseline LAST**, after Phase A + the A8 upgrade, so it reflects the hardened state.
- **Verify → Expected:** `sudo aide --check` returns no unexpected changes on a clean box.
- **Rollback:** `sudo apt-get purge --auto-remove aide aide-common` (log per §A7).

---

## §A11 — EGRESS CONTROL (new; default = visibility, restrictive = optional module)

The base runbook firewalls INPUT/FORWARD but leaves `OUTPUT ACCEPT` wide open — the primary **exfiltration / C2 path** after a compromise. Egress lockdown is omitted from universal Phase A on purpose (it breaks apt/DNS/updates without knowing the workload), so this is staged.

> **Lockout note:** a restrictive `OUTPUT` policy does **NOT** sever your inbound SSH session — SSH replies are `ESTABLISHED,RELATED` and the first OUTPUT rule allows them. It CAN break outbound services (apt, DNS, webhook, NTP). Arm a revert timer anyway and verify `apt-get update` works before persisting.

### A11.1 — Default everywhere: log dropped inbound (scan visibility)
Add as the **last INPUT rule, immediately before `-P INPUT DROP`** (mirror into ip6tables):
```
iptables  -A INPUT -m limit --limit 5/min -j LOG --log-prefix "ipt-drop-in: " --log-level 4
ip6tables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "ipt6-drop-in: " --log-level 4
```
- **Verify → Expected:** `journalctl -k | grep ipt-drop-in` shows hits after an external port scan; rate-limited so it can't flood the journal.
- **Re-persist:** changes the saved ruleset → re-run `sudo netfilter-persistent save`.

### A11.2 — Restrictive OUTPUT allow-list (OPTIONAL; strict + known egress profile only)
- **Skip-if:** egress is unknown/dynamic (keep A11.1 only), or a forwarding workload (VPN/relay) needs arbitrary egress.
- **Apply (arm the revert timer FIRST):**
  ```
  sudo systemd-run --on-active=300 --unit=egress-revert sh -c 'iptables -P OUTPUT ACCEPT; ip6tables -P OUTPUT ACCEPT'
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
  iptables -P OUTPUT DROP
  ```
  Then prove egress works (`sudo apt-get update`, `resolvectl query example.com`, webhook if used). Only then disarm: `sudo systemctl stop egress-revert.timer && sudo systemctl reset-failed 'egress-revert.*' 2>/dev/null || true`, and `sudo netfilter-persistent save`.
- **Verify → Expected:** `iptables -S OUTPUT` shows the allow-list before `-P OUTPUT DROP`; apt/DNS/NTP work; `curl --max-time 5 http://<random-host>:4444` times out.
- **Rollback:** the armed `egress-revert` timer, or `iptables -P OUTPUT ACCEPT; ip6tables -P OUTPUT ACCEPT` and re-save.

---

## §A12 — OS-LEVEL HARDENING (new; OPTIONAL strict-only — review breakage notes)

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

## §V-ADD — VERIFICATION MATRIX ADDITIONS

| Area | Command | Expected |
| --- | --- | --- |
| Console password not leaked | `history \| grep -c <user>`; transcript review | `0`; absent from files and logs |
| AllowGroups login | `[LOCAL]` new key session as admin | succeeds; `sshd -T \| grep allowgroups` = `sshusers` |
| cloud-init neutralized | `cloud-init status` (post-A8) | disabled; A2/A4 unchanged |
| auditd | `sudo auditctl -l` | rules listed; `ausearch -k sshd_config` returns events |
| Login notify | login → `journalctl -t ssh-login-notify -n1` | login line present |
| Inbound-drop logging | `journalctl -k \| grep ipt-drop-in` | scan hits logged, rate-limited |
| Egress (if restrictive) | `apt-get update`; `curl --max-time 5 http://<host>:4444` | apt works; high-port egress times out |
| Module blacklist | `modprobe -n -v dccp` | `install /bin/true` |
| Mount hardening | `findmnt /dev/shm` | `nodev,nosuid,noexec`; apt installs |

---

## Summary

- **§1-FIX / §A2-FIX** → corrections that supersede the matching base steps. Do these.
- **§A2.5 cloud-init**, **§A6.5 DNS** → small universal additions.
- **§A10 detection** → universal; the biggest conceptual gap in the base runbook.
- **§A11 egress** → A11.1 universal (visibility), A11.2 optional (containment).
- **§A12 OS-hardening** → optional strict-only; each item has a breakage tradeoff.

Net effect: shifts the model from "don't lock yourself out + close inbound" toward also "notice when someone gets in, and contain what they can do once they're in."

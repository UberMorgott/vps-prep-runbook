# VPS-PREP-RUNBOOK

An AI-agent runbook to **harden, tune and clean a fresh Ubuntu 24.04 / 26.04 VPS** over SSH — turning a default scan-magnet host into a locked-down, max-throughput, junk-free box, without pre-installing any workload.

Works on a **greenfield** box (fresh reset) and on a **brownfield** box that already runs a workload (VPN, Docker, web, DB, …): a mandatory read-only pre-flight discovery (§0.5) inventories what is already there and adapts the firewall / forwarding / cleanup steps so a live service is never severed.

The full procedure is in **[`VPS-PREP-RUNBOOK.md`](./VPS-PREP-RUNBOOK.md)**.

## Launch — paste this to your AI agent

```text
Execute the hardening runbook in this repo (VPS-PREP-RUNBOOK.md) verbatim against my VPS over SSH.

Access:  host=<HOST_IP>  user=root  auth=<password OR path-to-ssh-key>
Controller: <Windows/PowerShell | Linux/macOS>, key auth preferred.

Rules:
- Run §0.5 pre-flight discovery FIRST (read-only). Classify greenfield vs brownfield.
  If brownfield (existing VPN/Docker/web/DB/etc.): STOP, show me the inventory, and apply
  the §0.5 adaptation matrix — never break or auto-expose a running service.
- Follow the load-bearing order A1 -> A9; the A8 reboot is LAST.
- Before each lockout-capable step (A1 firewall, A2 sshd, A5 rp_filter) arm the server-side
  systemd-run rollback timer, verify access from a SECOND independent SSH session, then disarm.
- Before A8 reboot, confirm firewall/sshd/sysctl are persisted to disk. Anchor reconnect on boot_id.
- Verify every step with real command output. Never print or log my password.
- No workload answers => stop after Phase A (B-none): the box is hardened, tuned, clean, auto-patched.
```

## Scope

- **Phase A (universal baseline):** firewall (iptables-nft, v4+v6) · SSH crypto hardening (drop-ins, PQ KEX, key-only, root locked) · fail2ban · network tuning (BBR, buffers) · kernel hardening (sysctl) · maintenance (journald, NTP, AppArmor) · cleanup (purge bloat) · full-upgrade + reboot · unattended security updates.
- **Phase B (conditional):** workload modules (web / VPN / relay / fileshare) added only after Phase A, only if needed.

## Safety model

Designed to be driven by a **stateless one-shot executor** (CLI agent / paramiko / plink) with no continuously-open session. Recoverability rests on **server-side rollback timers** armed before each risky change plus a **second-session verify** — not on "keeping a session open". The only console-critical gate is the A8 reboot.

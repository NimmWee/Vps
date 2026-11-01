# Lightweight VK TURN installer

## Objective

One root command on Ubuntu 24.04 or Debian 12+ installs an authenticated FreeTurn UDP transport, kernel WireGuard and SSH Fail2ban, then produces independent Android FreeTurn and iPhone VK TURN Proxy import links. The small VPS does not build Go, run Docker, host a web panel or keep a VK call open.

## Architecture and choices

Default lightweight mode installs only apt runtime dependencies and a pinned, checksum-verified transport binary. A single FreeTurn daemon serves both phone apps with rtpopus3 / iOS SRTP-WRAP-S. WireGuard uses a dedicated interface, subnet, port and tagged firewall rules. The existing KIT, firewall, SSH configuration and default route remain intact. An explicit `--with-kit` option invokes a pinned upstream KIT installer first; it is not the lightweight default because KIT adds a panel and other processes.

Alternatives considered: container deployment adds a runtime and networking complexity; building Go on the VPS needs more RAM and disk. Shipping a small pinned artifact with its source and reproducible build instructions is chosen. No custom mobile application or second iOS server is required.

## Lifecycle and migration

The installer validates OS, resources, architecture, IP, ports and subnet before changing services. It records a root-only backup, keeps secrets in root-owned files, and enables systemd services. Re-running on an owned installation preserves keys and regenerates profiles for a changed public IP. Existing unrelated installations cause a clear stop rather than being overwritten.

`vps-vk backup` writes an encrypted backup outside the server only after the user downloads it; `vps-vk restore PATH` restores this project's validated configuration on a new host and substitutes its public IP. Existing phones need reimported links after a literal IP change. A domain endpoint is optional but cannot guarantee transparent migration across cached mobile profiles. Fresh installs rotate all VPN keys by default.

## Security and load

Fail2ban SSH policy: 3 failures in 600 seconds, fixed 30-day ban, database retained 35 days. Existing other jails are preserved. No SSH authentication changes or permanent administrator allowlist. Backend WireGuard is blocked externally; VPN access to the server, private ranges and IPv6 forwarding is blocked. Daemon runs without root and with memory limits. No panel, DNS tunnel, auto updater or telemetry in lightweight mode.

## Verification

Unit tests cover validation, links, safe backups/restores, secret redaction and migration. Shell syntax and Python compile checks run locally. Integration runs on the authorized VPS using isolated ports/subnet; it covers a repeated install, restarts, encrypted backup/restore to a sandbox and real VK TURN → WireGuard → DNS/HTTPS exit. No test is presented as a physical iPhone/Android or mobile whitelist test.

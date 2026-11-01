# One-command VPN installation plan

**Goal:** Publish a small, repeatable VK TURN deployment at NimmWee/Vps and deliver tested phone imports for the authorized server.

**Architecture:** Bash bootstrap verifies a pinned source bundle and binary. A Python standard-library CLI owns installation, profiles and encrypted backups; systemd and scoped firewall rules provide persistence. No build tools on the VPS.

**Tech stack:** Bash, Python 3 standard library, FreeTurn, WireGuard tools, iptables/nftables, Fail2ban, OpenSSL.

Implementation is executed in the dedicated empty repository checkout. No subagents are used, consistent with the user's recorded working preference. Architecture and publishing are already delegated by the current request; routine implementation decisions do not need another approval gate.

- [ ] Finish the current server's packet and VK relay tests, then revoke temporary access.
- [ ] Write failing tests for input validation, separate phone profiles, IP migration and hostile backup entries.
- [ ] Implement bootstrap, runtime CLI, systemd/network templates and artifact manifest.
- [ ] Implement install/status/profiles/backup/restore/uninstall and optional pinned KIT setup.
- [ ] Run unit tests, syntax checks, real installation in an isolated namespace/directory, repeated install and service restart tests.
- [ ] Audit tracked files for credentials and provide Russian usage and migration instructions.
- [ ] Commit, push to the requested repository, fetch the published one-command installer and verify checksums.
- [ ] Deliver phone configs and installation command; stop the completed heartbeat.

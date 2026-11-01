# Release verification — v1.0.0

Verified on 2 November 2026 (Asia/Tomsk).

- Python core tests: 8 passed, including independent phone keys, SRTP-WRAP-S / rtpopus3 import formats, IP change, schema validation, symlink rejection and authenticated encrypted backups.
- Go upstream tests: config, clientsdb, wire profiles, UDP server and server command passed with the key-file patch and pinned dependency updates.
- Source govulncheck: no reachable or imported-package findings; one advisory exists in a required module's unused package. This is a scoped dependency scan, not proof of complete security.
- Both Linux amd64 and arm64 binaries built. Only amd64 executed on a VPS.
- Real Ubuntu 24.04 amd64 VPS, 1 vCPU / about 1 GiB RAM: isolated fresh instance, repeated installation preserving credentials, service restart, encrypted backup/restore preserving keys and replacing the endpoint, and corrupted-backup rejection passed.
- Direct iOS-compatible transport → kernel WireGuard → DNS/HTTPS returned the VPS IPv4 and HTTPS 200 before/after repeated installation and restart.
- Existing SSH, x-ui, nginx and kit-sub process IDs and restart counters stayed unchanged during integration testing. Temporary integration services and interfaces were removed.
- UFW reload preserved the scoped firewall rules. SSH Fail2ban effective policy is 3 retries / 600 seconds / 2,592,000 seconds; manual test ban/unban was checked in nftables.

Full VK bootstrap from the datacenter test client requested a CAPTCHA. That relay test did not complete, and no physical iPhone/Android or mobile whitelist test is claimed. Solve any CAPTCHA in the mobile client, then validate on the actual network. No full VPS reboot, new KIT installation, Debian or arm64 VPS execution was tested.

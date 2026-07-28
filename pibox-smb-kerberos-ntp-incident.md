# Incident Write-Up: SMB Share Inaccessible — Cascading NTP → Kerberos → Machine-Account Failure

**Host:** `pibox.example.com` (Raspberry Pi, OpenMediaVault, domain-joined to `example.local` via winbind)
**Domain:** `example.local` (DCs: `dc01` 10.0.0.7, `dc02` 10.0.0.6)
**Date:** 2026-07-28
**Severity:** Service outage (single host) — SMB share unavailable to clients

---

## Summary

An SMB share on a domain-joined OMV host became inaccessible, surfacing to clients as *"the domain isn't available."* The presenting error pointed at Active Directory availability, but the domain and its controllers were fully healthy. Root cause was an **8-minute clock skew** on the host that pushed it outside the Kerberos 5-minute tolerance, causing all ticket validation to fail. The skew existed because the host had **never successfully synced time** — its NTP requests to the network's time source (the MikroTik router) were being silently dropped by the router's firewall input chain.

Fixing the clock did **not** restore service, because a **second, masked failure** had accumulated during the outage: while the host could not complete Kerberos, its AD machine-account password rotation never completed, leaving the locally stored machine secret out of sync with AD. This required a domain rejoin to reset.

Two independent fixes were required: (1) open UDP 123 on the router firewall so the host could sync time, and (2) rejoin the domain to resync the machine-account secret.

---

## Impact

- SMB share on `pibox` unreachable by clients; mapped drive returned "Location is not available / domain isn't available."
- A peer host (`nas`, same subnet, same domain) was unaffected — its clock was in sync, isolating the problem to `pibox`.

---

## Root Cause Analysis

The failure was a **cascade of two linked root causes**:

### Cause 1 — Clock skew breaking Kerberos
- `pibox` was **8 minutes behind** domain time (verified against a known-good domain clock).
- Kerberos rejects authentication when client/server clocks differ by more than **5 minutes** (default skew tolerance).
- Result: every ticket request for the host's SMB service failed, surfacing as "domain isn't available."

### Why the clock was wrong — blocked NTP
- `chronyd` on `pibox` had **never synchronized** (`Leap status: Not synchronised`, `Ref time: 1970`, all sources `Reach 0`).
- The host's configured time source was the MikroTik router (network's designated NTP server).
- The router's NTP **server was enabled and healthy**, and the router itself was **synced upstream** (stratum 1).
- However, the router's firewall **`input` chain** had no rule permitting UDP 123. Requests hit `input`, matched no accept rule, and were caught by the final `drop all else`. The NTP service never saw them.
- Key distinction: NTP to the router is **input-chain** traffic (destined for the router itself), which is a separate rule set from the **forward-chain** inter-VLAN rules. Prior firewall work had not opened this path.

### Cause 2 — Desynced machine-account secret (masked by Cause 1)
- AD rotates computer-account passwords periodically (default ~30 days).
- Because `pibox` could not complete Kerberos while its clock was broken, a machine-account password rotation could not complete, leaving the **local machine secret out of sync with AD**.
- Fixing the clock did **not** fix this — the secret remained broken.
- Forcing `net ads testjoin` directly at a DC exposed the true error:
  `Kinit for PIBOX$@EXAMPLE.LOCAL ... Preauthentication failed: NT_STATUS_LOGON_FAILURE`
  — a machine-account credential mismatch, previously masked as `DOMAIN_CONTROLLER_NOT_FOUND` / "no logon servers available."

---

## Diagnostic Path

The problem was walked down the stack rather than guessed, ruling out each layer in turn:

1. **DNS / SRV records** — `nslookup -type=srv _ldap._tcp.example.local` from the host resolved both DCs correctly. DNS ruled out.
2. **Reachability** — `nc -zv` to each DC on 88 (Kerberos), 389 (LDAP), 445 (SMB), 3268 (GC) succeeded over **both IPv4 and IPv6**. Firewall/routing to the DCs ruled out.
3. **Clock** — `chronyc tracking` showed never-synced state; `date` comparison vs a domain clock confirmed the 8-minute skew. **Cause 1 identified.**
4. **NTP path** — `chronyc sources` showed all sources `Reach 0`; `chronyc ntpdata` later showed the router replying but the router's own firewall was dropping the request pre-service. **Firewall input chain identified.**
5. **Trust secret** — after the clock fix, `wbinfo -t` and `net ads testjoin` still failed; forcing at `dc01` revealed `PIBOX$` preauth `LOGON_FAILURE`. **Cause 2 identified.**

---

## Resolution

### Fix 1 — Permit NTP on the router firewall (input chain)

IPv4:
```
/ip firewall filter add chain=input protocol=udp dst-port=123 \
  in-interface-list=LAN action=accept \
  comment="NTP clients" place-before=[find where chain=input action=drop comment~"all else"]
```

IPv6 (separate rule set; placed before the input-chain `drop all else`):
```
/ipv6 firewall filter add chain=input protocol=udp dst-port=123 \
  in-interface-list=LAN action=accept comment="NTP clients v6" place-before=5
```

Then, on the host, force immediate sync once a source was reachable:
```
sudo systemctl restart chrony
sudo chronyc burst 4/4
sudo chronyc makestep
chronyc tracking     # -> Leap status: Normal, real Ref time
```

### Fix 2 — Rejoin the domain to reset the machine-account secret
```
sudo net ads join -U Administrator
# -> Joined 'PIBOX' to dns domain 'example.local'

sudo systemctl restart winbind smbd
sudo net cache flush
sudo wbinfo -t       # -> trust secret ... succeeded
sudo net ads testjoin # -> Join is OK
```

Share access restored.

---

## Causal Chain

```
Firewall input chain drops UDP 123
        │
        ▼
chrony never syncs  ──►  8-minute clock skew
        │                        │
        │                        ▼
        │              Kerberos fails (outside 5-min tolerance)
        │                        │
        │                        ├──►  SMB share auth fails  ("domain isn't available")
        │                        │
        │                        └──►  machine-account password rotation cannot complete
        │                                        │
        ▼                                        ▼
   [Fix 1: open UDP 123]              machine secret desyncs from AD
   clock corrected                              │
        │                                        ▼
        │                              still fails after clock fix
        │                                        │
        │                              [Fix 2: net ads join] resets secret
        ▼                                        ▼
                    Trust OK ──► SMB share restored
```

The non-obvious element: the two failures were **linked in time** (one caused the conditions for the other) but required **independent remediation**. Fixing the visible cause did not clear the symptom.

---

## Lessons / Hardening

- **"Domain isn't available" is frequently a Kerberos error, not a connectivity error.** Check clock skew and machine-account trust before chasing network/DNS.
- **NTP to a router is input-chain traffic**, distinct from inter-VLAN forward-chain rules. Segmented networks must explicitly permit UDP 123 to the time source. Any new subnet will hit the same wall until the rule covers it (or the interface is added to the `LAN` interface-list the rule matches).
- **A masked cause can survive the fix for the visible cause.** After correcting time, re-verify the trust (`wbinfo -t`, `net ads testjoin`) rather than assuming the auth chain recovered on its own.
- **Recommended monitoring:** alert on `chronyc tracking` leap-status != Normal (or large offset), and periodic `wbinfo -t` on domain-joined Linux hosts. A silent time drift should surface before it breaks authentication and cascades into a secret desync.

## Open Items (non-blocking)

- Dynamic DNS registration of `pibox.example.local` failed during rejoin (`ERROR_DNS_INVALID_MESSAGE`), likely because the AD zone requires secure dynamic updates that the Samba update attempt did not satisfy. Not required for share access. Revisit if `.local` name resolution for the host is desired.
- Time-server list on the host still includes several gateway IPs that do not serve NTP (harmless `Reach 0` noise); trim to the working source(s) for cleanliness.

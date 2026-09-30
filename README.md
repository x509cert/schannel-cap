# Schannel/TLS PQC Telemetry

**Author:** Michael Howard — Azure Security PQC team — <mikehow@microsoft.com>

Capture per-connection TLS handshake telemetry on Windows and correlate it into
one view: **PID, source/dest IP, cipher suite, and the negotiated group** —
including PQC hybrids such as `X25519MLKEM768` (`0x11EC`).

Everything is **out-of-process** (ETW + packet capture). No DLL injection, no
code patching, nothing that a hardened/CLR-hosted server (e.g. Kestrel) can
reject.

---

## Quickstart

```powershell
# 1. build (VS tools)
build.cmd

# 2. capture       
powershell -ExecutionPolicy Bypass -File start-sch.ps1 -Port 8443   
#    ... from ANOTHER host:  curl --http1.1 -k https://<server-ip>:8443/

# 3. stop + colored table
powershell -ExecutionPolicy Bypass -File stop-sch.ps1    
```

Common variations:

```powershell
# tightest capture: one port between two known hosts (smallest log)
start-sch.ps1 -Port 8443 -IpA 192.168.1.168 -IpB 192.168.1.52

# capture everything (no filter)
start-sch.ps1

# decode only handshakes involving one IP
stop-sch.ps1 -FilterIp 192.168.1.52

# mask the second and third octets of source and destination IPv4 addresses
stop-sch.ps1 -MaskS -MaskD

# show only failed Schannel operations
stop-sch.ps1 -FailuresOnly

# omit table rows containing any listed string (case-insensitive)
stop-sch.ps1 -RedactStrings 'OUTLOOK.EXE','20.94.35.60'

# run the decoder by hand on any pcapng (text, or CSV)
tls_group.exe tls.pcapng connections.txt
tls_group.exe tls.pcapng connections.txt 192.168.1.52 -csv
```

Must run from an **elevated PowerShell window** (Run as administrator). Both
scripts stop with an error if not elevated; they do not prompt or self-elevate.
Same-box `127.0.0.1` traffic isn't
captured on this machine class — drive the handshake from another host (see
[Same-machine limitation](#same-machine-limitation-important)).

---

## Contents

| File | What it is |
|------|------------|
| `schannel_etw.cpp` | C++ ETW listener. Continuously snapshots the TCP table into `connections.txt` for the PID join and writes Schannel warning/error/critical events to `schannel_failures.csv`. `-v` also dumps raw Schannel/TCPIP events (self-describing via TDH). |
| `tls_group.cpp` | C++ pcapng parser that pulls the negotiated cipher + group out of each ServerHello and attaches the owning PID from `connections.txt`. |
| `build.cmd` | Builds `schannel_etw.exe` and `tls_group.exe`. |
| `start-sch.ps1` | Starts pktmon capture + the ETW listener. Requires an elevated PowerShell window. |
| `stop-sch.ps1` | Stops capture, converts ETL→pcapng, and prints the correlated result. Requires an elevated PowerShell window. |
| `README.md` | This file. |

---

## Dependencies

- **Windows** with in-box `pktmon`:
  - Client: Windows 10 1809+ (packet capture 2004+) / Windows 11.
  - Server: Windows Server 2016, 2019, 2022, 2025 — `pktmon` ships in-box on
    all of them, and every other API used here (ETW, TDH, `GetExtendedTcpTable`,
    PowerShell) is present too, so the toolset runs on Server unchanged.
- **Visual Studio Build Tools** with the C++ toolchain (`cl.exe`) — any arch;
  these tools are out-of-process so the build arch need not match the traffic.
  - Libraries used (all part of the Windows SDK, no third-party): `tdh.lib`,
    `advapi32.lib`, `iphlpapi.lib`, `ws2_32.lib`.
- **Administrator rights** — ETW sessions and pktmon require elevation. Open
  PowerShell with **Run as administrator** before running the `.ps1` scripts.
- **PowerShell** to run the scripts. On a fresh box, launch with
  `-ExecutionPolicy Bypass` (see below) or `Unblock-File *.ps1` once.

No Wireshark/Npcap required. (If Npcap is installed it does not interfere with
this pktmon-based flow, but note the loopback caveat below.)

---

## Build

From a **Visual Studio Native Tools** prompt (or any shell with `cl` on PATH):

```
build.cmd

# opt-in deep MSVC static analysis for both binaries
build.cmd /analyze
```

Produces `schannel_etw.exe` and `tls_group.exe` in this folder.

---

## Run

```powershell
# 1. start capture (run from an elevated PowerShell window)
powershell -ExecutionPolicy Bypass -File start-sch.ps1

# 2. generate a TLS handshake against the server you want to observe
#    (see "Same-machine limitation" -- drive it from ANOTHER host)
curl --http1.1 -k https://<server-ip>:8443/       # from another machine

# 3. stop + decode
powershell -ExecutionPolicy Bypass -File stop-sch.ps1
```

Optional filters:

```powershell
# only build the connection map / dump for one PID (diagnostic)
powershell -ExecutionPolicy Bypass -File start-sch.ps1 -FilterPid 100104

# only show handshakes involving one IP (matches either endpoint)
powershell -ExecutionPolicy Bypass -File stop-sch.ps1 -FilterIp 192.168.1.52
```

**Shrink the capture (recommended).** By default everything is captured, which
makes `tls.etl` large. If you know the server port (and ideally both hosts),
filter at the pktmon layer so noise never hits disk:

```powershell
# only TCP 8443 between these two hosts
powershell -ExecutionPolicy Bypass -File start-sch.ps1 -Port 8443 -IpA 192.168.1.168 -IpB 192.168.1.52

# just the port is usually enough to drop the :443 browser/telemetry noise
powershell -ExecutionPolicy Bypass -File start-sch.ps1 -Port 8443
```

`-Port`, `-IpA`, `-IpB` become one pktmon filter entry whose conditions are
AND-ed (traffic on that port **and** between those IPs). Packet size is kept
full — a PQC-hybrid ServerHello's `key_share` is ~1.1 KB, so truncating would
lose the group; the size win comes from dropping non-matching connections, not
from shortening packets.

If the server transfers large response bodies and the ETL is still big after
port-filtering, capture only the handshake window: run `stop-sch.ps1` a second
or two after the connection is made. `tls_group` only needs the ServerHello
(sent at the very start of the handshake), so you don't need the rest of the
session on disk.

Example output from `stop-sch.ps1`:

```
20:26:36.151  pid=100104(srv)  192.168.1.168:8443 -> 192.168.1.52:59618  cipher=0x1302(TLS_AES_256_GCM_SHA384)  group=0x11EC(X25519MLKEM768)
```

`stop-sch.ps1` renders the result as a PowerShell table, one row per connection
(duplicate captures from multi-point capture are collapsed), with **per-cell
color** via `$PSStyle`:

- Successful ServerHello rows have `Result=Success`. Schannel events at warning,
  error, or critical level have `Result=Failure`, a red Result cell, and include
  their ETW `EventId`, `Level`, and decoded properties in `Error`.
- Pass `-FailuresOnly` to display only failure rows:

  ```powershell
  stop-sch.ps1 -FailuresOnly
  ```

  Schannel failure events do not reliably contain a TCP connection tuple, so
  their Source and Dest values are `?`. `-FilterIp` filters successful packet
  rows only; use `-FailuresOnly` to isolate failures.
- `-MaskS` and `-MaskD` independently mask source and destination IPv4
  addresses by replacing the second and third octets with `XXX` (for example,
  `192.168.1.52:59618` becomes `192.XXX.XXX.52:59618`). IPv6 addresses and names
  produced by `-Resolve` are left unchanged.
- `-RedactStrings` omits any table row containing one or more supplied strings.
  Matching is literal and case-insensitive and applies to the displayed values,
  including masked endpoints and reverse-DNS names produced by `-Resolve`.
- The **Version** cell turns **red** on **TLS 1.2** (a migration/compliance flag).
- The **Group** cell turns **green** for a **TLS 1.3 PQC hybrid** (or pure-PQC)
  group; otherwise default.
- The **Cipher** cell turns **orange** for a **TLS 1.3** suite at the 128-bit
  tier (`AES_128` / `SHA256`) — i.e. weaker than `AES_256_GCM_SHA384`.

Per-cell color needs **PowerShell 7.2+** (where `Format-Table` is ANSI-aware).
On Windows PowerShell 5.1 it falls back to a plain, uncolored table. The table
uses `-Wrap`, so the Group column is never truncated (it wraps on a narrow
console rather than showing `…`). `Source` is the client, `Dest` is the server
(connection direction). The Group shows the group **name**; the raw `0xXXXX`
codepoint is shown only when the group isn't recognized. **Process** is the
owning process image name (e.g. `KestrelTls13.exe`), resolved live during
capture; it falls back to the PID when the name can't be read (protected/exited
process). The raw numeric PID is still in the CSV.

```
Time          Process              Source               Dest                 Version  Cipher                        Group
20:26:36.151  KestrelTls13.exe     192.168.1.52:59618   192.168.1.168:8443   TLS1.3   TLS_AES_256_GCM_SHA384        X25519MLKEM768   (green)
20:26:37.002  OUTLOOK.EXE          192.168.1.176:56181  20.94.35.60:443      TLS1.2   ECDHE_RSA_AES128_GCM_SHA256   none             (Version red)
```

The full capture is left at `tls.pcapng` — open it in Wireshark for
packet-level detail.

You can also run the decoder directly on any pcapng (text output, or `-csv`):

```
tls_group.exe tls.pcapng connections.txt [filter-ip] [-csv]
```

---

## Recognized groups

`tls_group` names these; any other codepoint prints as `0xXXXX(?)` (the value is
always shown, so unknown groups are still visible — tell the author to add it).

**PQC hybrid (ECDHE + ML-KEM), per draft-ietf-tls-ecdhe-mlkem:**

| Codepoint | Name | Combines |
|-----------|------|----------|
| `0x11EC` (4588) | `X25519MLKEM768` | X25519 + ML-KEM-768 — the de-facto default |
| `0x11EB` (4587) | `SecP256r1MLKEM768` | secp256r1 (P-256) + ML-KEM-768 — FIPS pairing |
| `0x11ED` (4589) | `SecP384r1MLKEM1024` | secp384r1 (P-384) + ML-KEM-1024 — CNSA 2.0 target |
| `0x6399` (25497) | `X25519Kyber768Draft00` | pre-standard hybrid (2023–24), superseded by `0x11EC` |

**Classical:**

| Codepoint | Name |
|-----------|------|
| `0x0017` | `secp256r1` (P-256) |
| `0x0018` | `secp384r1` (P-384) |
| `0x0019` | `secp521r1` (P-521) |
| `0x001D` | `x25519` |
| `0x001E` | `x448` |

To add a new group, extend `group_name()` in `tls_group.cpp`.

---

## How it works

The negotiated **group** is not present in Schannel's ETW events on current
builds — it only exists on the wire (the ServerHello `key_share`). So:

- **pktmon** captures packets → `tls_group` reads the ServerHello for the
  selected cipher + group.
- **`schannel_etw`** polls the TCP table (`GetExtendedTcpTable`) into `connections.txt`
  (`local remote PID processname`) → `tls_group` joins each ServerHello 4-tuple
  to the owning PID and process name. The name is resolved *live* during capture
  (`QueryFullProcessImageName`), because PIDs get reused — resolving it offline
  would be unreliable. `svchost.exe` shows as-is (shared service host; the
  specific service isn't broken out). Exact, loopback-safe, no ETW field-name
  guessing.
- **`schannel_etw`** also records Schannel warning, error, and critical ETW
  events in `schannel_failures.csv`. `stop-sch.ps1` merges these with successful
  ServerHello rows. Failure records preserve the event ID, severity, PID,
  process name, and decoded ETW properties, but show unknown endpoints when the
  provider does not emit a connection tuple.

**Why both?** The two sources answer different questions and neither alone is
enough. Packet capture is the only place the negotiated group appears in the
clear, but packets carry no process identity — so it can tell you *what* was
negotiated but not *who* negotiated it. The system side (the TCP table, opened
alongside an ETW session) supplies the missing process/PID and the client-vs-
server role by 4-tuple. Correlating the two gives the full picture — which
process, over which connection, negotiated which group — which is exactly what a
PQC-migration inventory needs (e.g. "which service is still on a classical group
or TLS 1.2"). If you only need what-was-negotiated, the packet capture stands on
its own and PID/side simply show `?`.

---

## Same-machine limitation (important)

Windows routes traffic between two local addresses through the **loopback
path**, which pktmon does not capture on a machine with no NDIS loopback
adapter. This applies to `127.0.0.1`, `::1`, **and the machine's own LAN IP**
when both ends are local. Result: a client and server on the *same box* produce
no packets pktmon can see.

**Drive the handshake from a different host on the LAN.** Bind the server to all
interfaces and connect from another machine:

- Server: listen on `0.0.0.0:8443` (Kestrel: `--urls https://0.0.0.0:8443` or
  `ListenAnyIP(8443, ...)`).
- Open the port + ICMP inbound in the firewall for the test.
- From another host: `curl -k https://<server-lan-ip>:8443/`.

That traffic crosses the physical NIC pktmon is bound to and is captured
normally. (`connections.txt` still resolves the PID because the server's socket is
local.)

**On a real server** this is usually a non-issue: a Windows Server accepting TLS
from remote clients is already receiving traffic across the NIC, so those
handshakes are captured without any workaround. The limitation only bites when
client and server are the **same machine** (dev-box testing).

---

## Notes

- Force HTTP/1.1 (`curl --http1.1`) to stay on TCP/Schannel; HTTP/3 is QUIC
  (msquic) and is not covered here.
- Very short-lived connections can close between 200 ms TCP-table polls, showing
  `pid=?`. Server listeners are stable, so the `srv` side resolves reliably.
- Repeated identical output lines are normal: pktmon captures at multiple points
  in the networking stack (especially with `--comp all`), so the same ServerHello
  can appear several times. Pipe through `sort -Unique` in PowerShell if you want
  one line per connection:
  `tls_group.exe tls.pcapng connections.txt | Sort-Object -Unique`
- `.ps1` execution policy: run with `-ExecutionPolicy Bypass` or
  `Unblock-File *.ps1` once after extracting.

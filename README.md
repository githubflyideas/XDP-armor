<div align="center">

# XDP-ban

**See it. Ban it.**

Governed XDP banning — in a single binary.

</div>

---

XDP-ban is a governed ban tool: submit a ban, approve it as a deliberate second step, and it executes in **XDP**, at the earliest point in the kernel, with escalating durations for attackers who keep knocking. Ships as a single static binary you can copy and run.

<div align="center">
<img src="docs/img/dashboard.svg" width="49%"/> <img src="docs/img/bans.svg" width="49%"/>
<img src="docs/img/ladder.svg" width="49%"/> <img src="docs/img/login.svg" width="49%"/>
</div>

## Features

- **Governed** — two-step approval, immutable audit log, one-time email approval links. Built for one person: one account, and you can approve your own request.
- **Escalating bans** — repeat offenders get progressively longer bans, up to permanent.
- **Scoped bans** — pick source ranges by **country / ASN**, protect a single target host. Impact is previewed and quota-checked before submission.
- **Pure XDP enforcement** — no nftables, no iptables. The agent writes eBPF maps directly, in **generic (SKB) mode** so it works on any NIC driver, not just the ones with native XDP support.
- **Answers "why is this host unreachable?"** — because the rules are invisible to `iptables`/`nft`/`firewalld` by design, the same binary ships `xdp-ban status` and `xdp-ban why <ip>`, reading the pinned kernel maps. It also refuses, on the first attempt, to accept a ban that would cut off the address you are submitting from.
- **Single binary** — pure Go, `CGO_ENABLED=0`, no external DB, no HTTP API surface. Copy and run.

## Architecture

One binary, control plane and enforcement together:

<div align="center">
<img src="docs/img/arch.svg" width="100%"/>
</div>

`xdp-ban` used to be split into a control plane and a separate `xdp-agent`
executor that polled the control plane's own HTTP API for orders. They've
been merged: `xdp-ban` now loads and attaches the XDP filter program itself
and executes approved bans directly against the database, no local HTTP
round-trip. Pass `-iface <ifname>` so it knows where to attach.

### The two paths that matter

Approval is the only way a ban comes into existence, and the XDP fast path is
the only place a ban has any effect. Both are worth reading closely:

<div align="center">
<img src="docs/img/approval.svg" width="49%"/> <img src="docs/img/packet-path.svg" width="49%"/>
</div>

On the left: all five decision entry points — four in the web UI, one via the
one-time email token — funnel through a single in-process mutex before the
transaction. The conditional `UPDATE ... WHERE state='pending'` stays as
defence in depth, but on its own it hands the losing request a 500 rather than
a 409, because SQLite fails the deferred transaction's write-lock upgrade with
`SQLITE_BUSY_SNAPSHOT`.

On the right: a packet destined for a host you never asked to protect is
released after two map lookups. TTL expiry is decided in the kernel by
comparing `expires_at` against `bpf_ktime_get_ns()` — there is no control-plane
sweeper, and the DB↔map divergence that follows is what the 5-minute reconcile
loop exists to detect.

## Quick start

Download the binary and run it. No dependencies, no build step — the eBPF objects are already inside.

```bash
# x86_64
curl -L -o xdp-ban https://github.com/githubflyideas/XDP-invisible-armor/releases/latest/download/xdp-ban-linux-amd64
# arm64: replace amd64 with arm64 in the URL above

chmod +x xdp-ban
sudo ./xdp-ban -iface eth0    # http://localhost:8080 — root needed to attach XDP
```

### Default account

One account is seeded on first run. **Change the password immediately** — it is
printed in this README and therefore public. Change it under **账号 / Account**;
that revokes every session, including your own.

| Username | Password |
|---|---|
| `admin` | `admin12345` |

There is exactly one account, and no user management. Submitting and approving
can be the same person, so there is nothing for a second role to do. The
`pending → approve` step is still there, but it exists to give you one chance to
change your mind and to let the audit log separate "when it was requested" from
"when it took effect" — not to force a second pair of eyes.

If you do need to give several people different levels of access, put it in
front of `xdp-ban` — a reverse proxy or a dedicated auth layer covers both the
web UI and the email approval links, which a role table inside the app never
did.

Data lives in a single `xdpban.db` file. Back up = copy the file.

All releases: https://github.com/githubflyideas/XDP-invisible-armor/releases

## Scoped bans (country / ASN)

```bash
curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz
XDPBAN_PREFIX_DB=./ip2asn-v4.tsv.gz ./xdp-ban
```

Without it, everything else works and the UI tells you the feature is unavailable.

## Troubleshooting: none of this shows up in `iptables`

XDP runs at the driver hook, **before netfilter**. That is the entire point — and
it also means `iptables -L`, `nft list ruleset` and `firewall-cmd --list-all`
will never list a single ban, no matter how much traffic is being dropped. If
those are the only places you look, a host that just banned your own `/24` looks
like an outage with no cause.

The same binary answers that from the console. Neither subcommand needs
`-iface`, neither needs the daemon to be running, and neither writes anything:

```bash
sudo xdp-ban status            # what the kernel is actually enforcing
sudo xdp-ban why 203.0.113.7   # is this address being dropped right now, and by which rule
```

`status` prints the XDP attachments it can find, the four kernel counters, and
every map entry **split into live and expired**. That split is the point: XDP
never deletes keys — it compares `expires_at` against `bpf_ktime_get_ns()` and
just passes the packet — so "the key is in the map" is *not* the same as "this
address is being dropped", and a raw `bpftool map dump` will happily lead you to
the opposite conclusion. A `dropped` counter of zero is stated explicitly,
because it exonerates XDP entirely and sends you to look elsewhere.

`why` asks the LPM trie the same question the kernel asks, so querying a single
address correctly reports the covering `/24` that is actually responsible, not
just an exact-match miss.

Both read the maps pinned under `/sys/fs/bpf/xdp-ban/`, which is the source of
truth — not the SQLite file, which only records what was *intended*. If you
don't have the binary at hand,
`bpftool map dump pinned /sys/fs/bpf/xdp-ban/src_ban_global` is the fallback.

### It won't let you cut yourself off by accident

Submitting a ban whose source range covers the address you are browsing from is
refused on the first attempt. The message names the prefix that matched and the
commands to undo it from a physical console, and the form comes back with a
checkbox to submit anyway — a deliberate self-ban is allowed, a mistyped `/24`
is not silently accepted. Ticking that box is recorded in the audit log together
with the address it came from, which is the only evidence that survives if the
UI then goes dark.

This matters most for scoped bans: nobody audits all 400 prefixes a country or
ASN expands into, so the check runs against the resolved list, not the selector.

The hard-protected set (`127.0.0.0/8`, `::1/128`, `0.0.0.0/32`, plus any
configured protected target) is checked *before* this and is **not** overridable
by that checkbox.

## Configuration

`xdp-ban` subcommands (read-only, no `-iface`, no root needed beyond map access):

| Command | Purpose |
|---|---|
| `xdp-ban status` | Snapshot of every rule the kernel holds, live vs. expired, plus counters |
| `xdp-ban why <ip>` | Whether that address is being dropped right now, and by which rule |
| `xdp-ban version` | Print the version |

Run with no subcommand to start the daemon (web UI + executor).

`xdp-ban` flags:

| Flag | Default | Purpose |
|---|---|---|
| `-iface` | — (required) | Production NIC to attach the XDP ban program to. No default — silently skipping this would mean bans stay in the approval log without ever blocking traffic. |
| `-poll-interval` | `5s` | How often to scan for newly-approved dispatches to execute |

`xdp-ban` environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `XDPBAN_DB` | `xdpban.db` | SQLite file path |
| `XDPBAN_ADDR` | `:8080` | Listen address |
| `XDPBAN_BASE_URL` | `http://localhost:8080` | Prefix for email approval links |
| `XDPBAN_IFACE` | — | Alternative to `-iface` |
| `XDPBAN_PREFIX_DB` | — | Path to `ip2asn-v4.tsv[.gz]`; enables scoped bans |
| `XDPBAN_COOKIE_SECURE` | — | Set to any value when behind TLS |
| `XDPBAN_PPROF` | — | Set to any value to expose `/debug/pprof` (bind to a private interface only) |
| `GIN_MODE` | `release` | Gin runs in release mode unless you set this. `GIN_MODE=debug` brings back the startup route dump — useful when a route isn't behaving, noisy otherwise. |

## Deploy with systemd

```bash
sudo cp xdp-ban /usr/local/bin/xdp-ban
sudo cp deploy/xdp-ban.service /etc/systemd/system/xdp-ban.service
sudo mkdir -p /var/lib/xdp-ban /etc/xdp-ban
echo 'XDPBAN_IFACE=eth0' | sudo tee /etc/xdp-ban/xdp-ban.env

sudo systemctl daemon-reload
sudo systemctl enable --now xdp-ban
```

Edit `/etc/xdp-ban/xdp-ban.env` (or the `ExecStart` line in the unit file
directly) to set the real production interface. `Restart=on-failure` restarts
the process on a crash; `systemctl restart xdp-ban` for deploys sends
`SIGTERM`, which triggers a graceful shutdown (drains in-flight HTTP requests,
stops the executor loop, detaches XDP) before the process exits.

The maps are pinned under `/sys/fs/bpf/xdp-ban/`, so live bans survive that
restart and `xdp-ban status` keeps working while the daemon is down. That needs
bpffs mounted — it is on every modern systemd distro; if it isn't, the daemon
logs a warning with the `mount -t bpf bpf /sys/fs/bpf` fix and keeps enforcing
bans without the diagnostic path. A **host** reboot clears bpffs entirely, and
the 5-minute reconcile loop reports the resulting drift.

The unit deliberately omits `ProtectSystem=strict` and friends: they make `/sys`
read-only, which breaks map pinning, and the failure mode is a service that
starts fine but shows nothing in `xdp-ban status`.

## Build from source

Only needed if you're hacking on it — released binaries already bundle the eBPF objects.
Requires `clang` and `libbpf-dev`.

```bash
make bpf      # clang → cmd/xdpban/obj/xdp_filter.o (embedded via go:embed)
make build    # xdp-ban; refuses to run if the .o file is missing
make check    # go vet + go test -race
make release  # bpf + check + cross-compile linux/{amd64,arm64}
```

The `.o` files are build artifacts, not tracked in git. `make build` asserts they
are non-empty, so a binary with empty bytecode can't be shipped by accident.

## License

Apache-2.0. See [LICENSE](LICENSE).

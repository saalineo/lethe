# LETHE
<div align="center">
  <img src="res/lethe.svg" alt="LETHE Logo" width="300" />
  
  <h1>LETHE</h1>
</div>
Ephemeral State-Machine Chat Terminal. Forensically deniable, zero filesystem footprint, locked-RAM messenger.

## What it does
**LETHE** is a two-party, peer-to-peer terminal chat and file pipe with **zero persistent state**.
- **Volatile execution**: secrets live in locked RAM (`mlockall`, `mlock`ed passphrase buffer), swap-proof.
- **No footprint**: no logs, config or history on disk; Tor state lives on a private RAM `tmpfs`.
- **Passphrase-authenticated**: a shared passphrase (Argon2id + SPAKE2 with key confirmation) authenticates the peers; messages use a one-way ratcheting ChaCha20-Poly1305 chain.
- **Traffic shaped**: constant 512-byte cells at a fixed 10 cells/s, noise when idle.
- **Over Tor**: optional onion-service transport (embedded arti), so neither side learns the other's IP.
- **Sandboxed**: the chat UI runs in a separate process with no keys, network or filesystem access; the core runs under a seccomp allow-list.
- **Secure shutdown**: `exit`/`quit`, SIGINT or SIGTERM wipe all key material.

## Quick Start

Requires Linux with user namespaces, `libseccomp`, and `setcap`.

```bash
make                    # build lethe + liblethe.so into target/release/
./util/setup_caps.sh    # setcap cap_ipc_lock,cap_sys_admin+ep (needs sudo, once per build)
```

Run from `target/release/` (the binary looks for `liblethe.so` next to itself, or pass `--lib <path>`).
It always needs a real terminal: the passphrase is read from `/dev/tty`, never from stdin or argv.

**Direct TCP (LAN / testing)**
```bash
./lethe --server --lib ./liblethe.so            # prompts for listen address [0.0.0.0:9000]
./lethe --lib ./liblethe.so                     # prompts for peer address  [127.0.0.1:9000]
```
`make run-server` / `make run-client` do the same on localhost. Both sides must enter the same passphrase.

## Three modes
Chosen automatically from what stdin/stdout are connected to (override with `--send` / `--recv`).

| Mode | Invocation | Notes |
|---|---|---|
| **Chat** | both stdin and stdout are terminals | sandboxed UI, alias questionnaire, `exit` to quit |
| **Send** | `cat file \| lethe ...` | streams stdin to the peer, waits for the receiver's ACK |
| **Receive** | `lethe ... > file` | writes the verified stream to stdout |

```bash
./lethe --server --lib ./liblethe.so > out.bin      # receiver
cat in.bin | ./lethe --lib ./liblethe.so            # sender
```
Files go RAM to RAM with no name or size on the wire; a SHA-256 trailer detects truncation. Verdicts print on
the terminal, never stdout. Exit codes: `0` verified, `1` local I/O error, `2` hash mismatch / bad frame / auth failure, `3` connection lost before completion.

## Over Tor: the onion-address flow
Add `--onion` on both sides (works in all three modes).

1. Server: `./lethe --server --onion --lib ./liblethe.so`. After the passphrase, Tor bootstraps (spinner; seconds to a minute) and the **ephemeral `.onion` address is printed on your terminal only**.
2. Send that address and the passphrase to the peer out-of-band (separately).
3. Client: `./lethe --onion --lib ./liblethe.so`, then type the address at the hidden prompt (it never touches argv or shell history; `--addr` exists for scripts but does).
4. The server accepts exactly **one** peer, then closes the service. It waits at most 10 minutes. The client retries with backoff.

Every server run generates a new `.onion` address. The address is only a way to reach the service; the passphrase is what authenticates. A wrong passphrase fails the handshake and both sides wipe and exit.

## Cost of traffic shaping
Every cell is 512 bytes (492 usable) sent every 100 ms in each direction, whether or not you type:
**5.12 KB/s, about 440 MB/day per direction**, and a throughput ceiling near **4.9 KB/s** (a 1 MB file takes
about 3.5 minutes). A typed line waits up to 100 ms plus any queue backlog. Over Tor this is on top of Tor's own overhead.

## What is NOT hidden
| Observer | Sees |
|---|---|
| Network (direct TCP) | both IP addresses, session start/end, total bytes |
| Network (Tor) | that you use Tor, and when; not who you talk to |
| Either, via timing | a file transfer looks like "the queue never empties"; the fixed 100 ms rhythm fingerprints the tool; TCP framing is unpadded |
| Hidden | when you type, message length (to 492-byte steps), idle vs. active |

Also: two parties only, no reconnect or resume; the symmetric ratchet gives forward secrecy within a session
but no recovery after a chain-key compromise; peer aliases are self-declared, not authenticated; the endpoint
itself (your machine, your terminal scrollback) is out of scope.

## Tor and Arti notes
- Tor is arti 0.47 (a Rust Tor implementation), embedded in `liblethe.so`; arti is younger than C Tor and its onion-service support is still evolving, so treat it as less battle-tested. Its dependency tree is large; the exact version is pinned and `Cargo.lock` is committed.
- Tor state, cache **and the onion identity key** are kept on a private `tmpfs` (`noswap` on Linux >= 6.4, otherwise a warning is shown) inside the process's mount namespace and released at shutdown. The key is therefore in RAM but **not mlocked or zeroized**: arti's in-memory keystore is experimental and did not work with onion services in 0.47.
- Needs only `cap_ipc_lock` and `cap_sys_admin`; no network capabilities.

## Development
```bash
make check    # clippy -D warnings + unit tests for both crates
```
The full binary cannot run under some sandboxes/CI (the ptrace watchdog turns a seccomp violation into exit 1).

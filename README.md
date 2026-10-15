# LETHE
<div align="center">
  <img src="res/lethe.svg" alt="LETHE Logo" width="300" />
  
  <h1>LETHE</h1>
</div>
Ephemeral State-Machine Chat Terminal. Forensically deniable, zero filesystem footprint, locked-RAM messenger.

## What it does
**LETHE** is a peer-to-peer chat terminal that maintains **zero persistent state**. 
- **Volatile Execution**: Everything runs in locked RAM (via `mlockall`).
- **No Footprint**: No logs, no config files, and no history are ever written to disk.
- **Secure Shutdown**: Instantaneously wipes all cryptographic material from memory upon exit.

## Quick Start

### 1. Build
```bash
make
```

### 2. Apply Privileges
Required for memory locking and namespaces.
```bash
./util/setup_caps.sh
```

### 3. Start
**Server:**
```bash
make run-server
```

**Client:**
```bash
make run-client
```

---
*Type `exit` in the terminal to trigger a secure memory wipe and shutdown.*

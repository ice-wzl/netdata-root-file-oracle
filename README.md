# Netdata Root File Oracle

**Reading Between the Logs: Turning Netdata Collectors into a Root File Oracle**

Security research demonstrating how Netdata's privileged `go.d.plugin` collectors can be abused to disclose root-readable files through attacker-controlled configuration and verbose logging.

**Researcher:** [ice-wzl](https://github.com/ice-wzl)  
**Conference:** BSides NoVA 2026 — October 31, 2026  
**CVE:** CVE-2026-XXXX (Pending Assignment)  
**Vulnerable Versions:** >= 1.45.0

## Overview

Netdata is an open-source infrastructure monitoring platform that collects metrics from operating systems, applications, and services.

To perform certain monitoring operations, Netdata deploys collectors with elevated privileges. One such component, `go.d.plugin`, may be granted the Linux capability `CAP_DAC_READ_SEARCH`, allowing it to bypass discretionary file-read and directory-search permission checks.

The issue arises from the combination of three behaviors:

1. **Privileged execution:** `go.d.plugin` has elevated file-read permissions.
2. **Attacker-controlled configuration:** The plugin accepts a custom configuration directory through the `-c` argument, allowing control over collector inputs.
3. **Information disclosure:** Certain collectors expose contents of files they process through parsing errors or debug messages.

By combining these behaviors, an attacker who can execute the privileged plugin can disclose files that would otherwise be inaccessible to their account.

### Affected Collectors

The research identified four collectors with file-disclosure behavior:

| Collector | Disclosure mechanism |
|---|---|
| `squidlog` | Up to the last 100 lines through debug logging |
| `web_log` | Up to the last 100 lines through debug logging |
| `prometheus` | 1st line of a file |
| `httpcheck` | 1st line of a file |

The included PoC demonstrates the `squidlog` disclosure path.

## Security Impact

**Prerequisites:**
- Local command execution as the `netdata` user or an account permitted to execute the privileged plugin.
- An installed `go.d.plugin` binary with sufficient file-read privileges, such as `CAP_DAC_READ_SEARCH`.
- Ability to invoke the plugin with an attacker-controlled configuration directory.
- A vulnerable collector and disclosure path.

**Result:**

Disclosure of protected file contents, including potentially:

- `/etc/shadow` password hashes
- SSH private keys
- Application credentials
- API tokens and other secrets

The `squidlog` PoC targets up to the last 100 lines of a specified file.

**This is a privileged file-disclosure vulnerability, not a demonstration of arbitrary command execution as root.**

## Proof of Concept

The PoC automates the setup of a malicious Netdata collector configuration and invokes the privileged `go.d.plugin` binary to demonstrate the file-disclosure behavior.

### Requirements

- Python 3
- Linux
- An affected Netdata installation
- Local access sufficient to execute the privileged `go.d.plugin`

### Usage

```bash
python3 netdata-file-oracle.py -h
```

```text
usage: netdata-file-oracle.py [-h] -b BASE_DIR -p PLUGIN_LOCATION -f FILE_NAME

POC for CVE-2026-XXXX

options:
  -h, --help
                        show this help message and exit
  -b, --base_dir BASE_DIR
                        Base directory used to create the configuration structure
  -p, --plugin_location PLUGIN_LOCATION
                        Path to Netdata's go.d.plugin binary
  -f, --file_name FILE_NAME
                        File to read (up to the last 100 lines)
```

### Example

The following demonstrates the PoC against `/etc/shadow` in an authorized test environment:

```bash
python3 netdata-file-oracle.py -b /tmp -p /usr/libexec/netdata/plugins.d/go.d.plugin -f /etc/shadow
```

**Arguments:**

| Argument | Description |
|---|---|
| `-b` | Base directory for the generated Netdata configuration |
| `-p` | Absolute path to the `go.d.plugin` executable |
| `-f` | Path to the file the collector will attempt to read |

### How It Works

At a high level, the PoC:

1. Creates a custom Netdata configuration directory.
2. Configures the `squidlog` collector to process a specified file.
3. Invokes the privileged `go.d.plugin` using that configuration.
4. Leverages debug logging to expose file contents that the invoking user could not otherwise read.

## Root Cause

The vulnerability exists at the intersection of privileged file access, user-controlled configuration, and verbose collector logging.

The `squidlog` collector reads the final 100 lines of a configured file when initializing its parser.

Within its `createParser()` function, the collector logs each nonblank line in debug mode before attempting to parse it.

```go
const readLastLinesNum = 100

lines, err := logs.ReadLastLines(
    c.file.CurrentFilename(),
    readLastLinesNum,
)
```

The security-relevant behavior occurs when file contents are written into debug output:

```go
c.Debugf("last line: '%s'", line)
```

When this code executes with elevated file-read capabilities and the attacker controls the filename, debug logging can become a disclosure channel.

The same underlying trust-boundary problem exists in other affected collectors, although their specific disclosure mechanisms differ.

## Responsible Disclosure

| Date | Event |
|---|---|
| July 13, 2026 | Initial private vulnerability report submitted to Netdata |
| July 15, 2026 | Additional collaborator added to the GitHub Security Advisory |
| August 24, 2026 | Follow-up requesting acknowledgement and communicating a 90-day disclosure timeline |
| October 2026 | Additional follow-up requesting remediation, CVE assignment, and disclosure status |
| October 11, 2026 | Researcher's stated 90-day disclosure window ends |
| October 31, 2026 | BSides NoVA 2026 presentation |

At the time of drafting, no substantive vendor response had been received in the advisory discussion following the researcher's requests for an update.

**Remediation status and affected versions will be updated following vendor confirmation and public disclosure.**

<div align="center">

# TheMasterBench

**One script. A full cross-platform forensics box. Rebuildable from scratch in under an hour.**

Turns a stock Kali install into a Windows / macOS / Linux digital-forensics workstation —
and puts it back exactly the same way after you burn the VM down.

[![Shell](https://img.shields.io/badge/shell-bash-4EAA25?logo=gnubash&logoColor=white)](#)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)](#)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![ShellCheck](https://img.shields.io/badge/shellcheck-passing-brightgreen?logo=gnubash&logoColor=white)](#)
[![Idempotent](https://img.shields.io/badge/idempotent-yes-success)](#)

<sub>19 modules · 200+ tools · zero manual steps</sub>

</div>

---

```bash
git clone https://github.com/YOURUSER/themasterbench.git
cd themasterbench
chmod +x themasterbench.sh
sudo ./themasterbench.sh --all
```

Roughly 30–60 minutes on a decent connection. Re-running is cheap — completed modules
are skipped unless you pass `--force`.

> [!TIP]
> Always start with `./themasterbench.sh --all --dry-run`. It prints every single action
> it would take and changes nothing.

---

## Contents

- [Why this exists](#why-this-exists)
- [Commands](#commands)
- [Modules](#modules)
- [Coverage by platform](#coverage-by-platform)
- [What lands on your box](#what-lands-on-your-box)
- [Design decisions](#design-decisions)
- [VM sizing](#vm-sizing)
- [Rebuild workflow](#rebuild-workflow)
- [After the first run](#after-the-first-run)
- [Known gaps](#known-gaps)
- [License](#license)

---

## Why this exists

A forensics VM should be disposable. You revert it between cases so artefacts from one
examination can't contaminate the next, and you rebuild it when a tool install goes
sideways. That only works if the build itself is a file you can version, diff and re-run.

This is that file.

It's deliberately **not** a `apt install` one-liner. Kali renames and drops packages
between releases, half the good DFIR tooling isn't packaged at all, and Python tooling on
a PEP-668 distro needs care. The script handles all three without falling over.

---

## Commands

| Command | What it does |
| :--- | :--- |
| `sudo ./themasterbench.sh --all` | Full build |
| `sudo ./themasterbench.sh --only core,windows,memory` | Just those modules |
| `sudo ./themasterbench.sh --all --skip ghidra,mobile` | Everything except the heavy bits |
| `sudo ./themasterbench.sh --all --force` | Redo completed modules (pulls tool updates) |
| `./themasterbench.sh --all --dry-run` | Print every action, change nothing |
| `./themasterbench.sh --verify` | Report which tools are present — no root needed |
| `./themasterbench.sh --list` | List modules |

---

## Modules

<details>
<summary><b>All 19 modules</b> — click to expand</summary>

<br>

| Module | Contents |
| :--- | :--- |
| `core` | Build toolchain, Python, pipx, common utilities |
| `hygiene` | Disable automount, group membership, `/cases` + `/evidence` tree, helper scripts |
| `acquisition` | dc3dd, dcfldd, ddrescue, guymager, ewf-tools, afflib, xmount |
| `filesystems` | NTFS/exFAT/HFS+/APFS/ext, LVM, BitLocker, FileVault, VSS, VHD/VMDK/QCOW |
| `carving` | foremost, scalpel, bulk_extractor, photorec, testdisk, binwalk |
| `triage` | dissect, plaso, Sleuth Kit, hashdeep, ssdeep, YARA |
| `memory` | Volatility 3 + symbol packs, MemProcFS, AVML, LiME |
| `windows` | RegRipper, regipy, evtx_dump, chainsaw, hayabusa, MFT/INDX/SRUM parsers, Sigma rules |
| `ez_tools` | Eric Zimmerman .NET suite via PowerShell *(best-effort)* |
| `macos` | apfs-fuse, unifiedlog_parser, mac_apt, plist tools, FSEventsParser |
| `linuxart` | auditd, journald, mac-robber, persistence artefact tooling |
| `browsers` | Hindsight, sqlite-dissect, DB Browser for SQLite |
| `email` | libpff (PST/OST), readpst, extract-msg, libratom |
| `malware` | YARA, capa, FLOSS, oletools, Didier Stevens suite, ClamAV, DIE, radare2 |
| `network` | Wireshark/tshark, zeek, suricata, tcpflow, scapy |
| `mobile` | iLEAPP / ALEAPP / RLEAPP |
| `collection` | Velociraptor offline collector workflow |
| `ghidra` | Reverse-engineering suite *(large download)* |
| `reporting` | CherryTree, pandoc, mkdocs, case templating |

</details>

---

## Coverage by platform

<table>
<tr><th width="140">Platform</th><th>Tooling</th></tr>
<tr><td><b>Windows</b></td><td>
RegRipper 3.0 and regipy for registry · <code>evtx_dump</code> and EvtxECmd for event logs ·
chainsaw and hayabusa for rule-based EVTX triage, with the SigmaHQ rule set cloned locally ·
analyzeMFT / MFTECmd / dfir-ntfs for <code>$MFT</code> · INDXRipper for directory-index slack ·
libscca for prefetch · liblnk for shortcuts and jumplists · libesedb for SRUM and Windows Search ·
libvshadow for shadow copies · libbde for BitLocker
</td></tr>
<tr><td><b>macOS</b></td><td>
<code>apfs-fuse</code> built from source, since Kali doesn't package it · mac_apt as the broad
artefact sweeper · Mandiant's <code>unifiedlog_parser</code> for <code>.tracev3</code> unified logs ·
libfvde for FileVault 2 · libplist and ccl-bplist for binary plists · FSEventsParser for the
filesystem event store
</td></tr>
<tr><td><b>Linux</b></td><td>
dissect's <code>target-*</code> tools read ext/XFS/Btrfs images directly · auditd and journald
tooling · <code>mac-robber</code> · the full Sleuth Kit stack
</td></tr>
</table>

### The one to actually look at

[**dissect**](https://github.com/fox-it/dissect) is the sleeper pick. `target-query -f <plugin>`
pulls normalised artefacts out of a Windows, Linux *or* macOS image with identical syntax and
identical output shape. It saves a genuine amount of context-switching versus running a
different parser per OS.

Plaso (`log2timeline.py` → `psort.py`) still does the super-timeline. Volatility 3 plus
MemProcFS covers memory for all three, with symbol packs pre-fetched at build time so you're
not downloading them mid-examination.

---

## What lands on your box

```
/opt/themasterbench/              third-party repos, built binaries, Volatility symbol packs
/opt/themasterbench/MANIFEST.md   generated inventory — every tool, path and version
/cases/                 per-case working directories
/evidence/              read-only mount points for source media
/var/lib/themasterbench/    module completion markers
/var/log/themasterbench.log provisioning log
```

Three helpers go on `PATH`:

**`bench-new-case`** — scaffolds a case tree with the evidence register and chain-of-custody
table already stubbed out.

```bash
bench-new-case CASE-2026-001 "laptop from HR referral"
```

**`bench-mount-ro`** — mounts read-only with `noexec,nodev,noatime`, plus `noload` so ext
journals are never replayed and `show_sys_files` so `$MFT`, `$LogFile` and `$UsnJrnl` are
visible on NTFS.

```bash
bench-mount-ro /evidence/disk0.E01
```

Plus wrappers for everything that would otherwise need a venv, a `dotnet` invocation or a
full path — `memprocfs`, `mftecmd`, `pdf-parser`, `mac-apt`, `ileapp` and friends.

---

## Design decisions

<details>
<summary><b>Packages install one at a time</b></summary>

<br>

Kali renames and drops packages between releases. One bad name in a 30-package
`apt install` line kills the entire call. Every package is checked against the cache and
installed individually; failures are collected into the manifest instead of aborting the run.

Expect a handful of *"not in repositories on this release"* warnings. That's the mechanism
working, not a broken script — check `MANIFEST.md` to see exactly which ones.

</details>

<details>
<summary><b>Python tooling goes through pipx, owned by your user</b></summary>

<br>

Kali is PEP-668 externally-managed. `pip install --break-system-packages` into the system
Python is precisely how you end up with a box that can't be rebuilt. Each tool gets its own
isolated venv, and repos that ship a `requirements.txt` get a dedicated venv plus a `PATH`
wrapper.

</details>

<details>
<summary><b>Auto-mounting is off and removable media is forced read-only</b></summary>

<br>

GNOME automount is disabled, udisks2 mount actions require admin auth, and a udev rule runs
`blockdev --setro` on newly attached removable block devices.

</details>

> [!WARNING]
> **The udev rule is a safety net, not a write blocker.** It won't stop firmware-level writes,
> it won't catch a device that enumerates as non-removable, and it will not help you defend
> the acquisition later. Use a hardware write blocker on original media. Comment out
> `/etc/udev/rules.d/99-themasterbench-removable-ro.rules` when you deliberately need write access.

---

## VM sizing

| Resource | Recommendation | Why |
| :--- | :--- | :--- |
| **RAM** | 16 GB min, 32 GB preferred | Plaso is the hog, especially alongside Volatility |
| **vCPU** | 8 | `log2timeline.py` and `bulk_extractor` both scale near-linearly |
| **Disks** | Three, not one | OS ~80 GB · evidence (attach read-only where the hypervisor allows) · working/output |
| **Working disk** | Fast, and generous | Timelines run several times the size of the source image |
| **USB** | Passthrough for physical media | And disable the hypervisor's own shared-folder automount |

---

## Rebuild workflow

The whole point is that the VM is disposable. Keep the state that matters *outside* it.

1. **This repo is your build definition.** Version it, diff it, trust it.
2. **Build, run `--all`, then snapshot before touching any evidence.** That snapshot is your
   clean baseline — revert to it between cases.
3. **Keep `/cases` on a separate virtual disk** or a host mount, so destroying the VM never
   destroys case data.
4. **To rebuild:** fresh Kali → `git clone` → `sudo ./themasterbench.sh --all` → reattach the
   case disk.

> [!NOTE]
> Compare the new `MANIFEST.md` against the one from the case you're continuing. Tool versions
> belong in your report, and this is the cheapest way to have them on hand.

Going fully hands-off from here means wrapping the script in a Packer shell provisioner, so
`packer build` emits a ready qcow2 or OVA.

---

## After the first run

Log out and back in. Group membership (`disk`, `fuse`, `wireshark`) and the pipx `PATH` entry
both need a fresh session.

Then:

```bash
./themasterbench.sh --verify     # quick green/red inventory
cat /opt/themasterbench/MANIFEST.md         # full detail, including what failed and why
```

Anything red is either a package your Kali release dropped or a build that didn't complete.
The manifest tells you which. Most are fixed by re-running the single module:

```bash
sudo ./themasterbench.sh --only macos --force
```

---

## Known gaps

Two things are deliberately left manual, because automating them would be worse than not:

- **NSRL / hash sets** — enormous, and licence terms vary by subset. Download the RDS subsets
  you actually need and index them for `hfind`.
- **Autopsy 4** — the Kali repo package is the old 2.x Perl version. If you want the current
  Java GUI, install it from the Sleuth Kit site; it wants its own JDK and a writable case
  directory.

---

## License

[MIT](LICENSE). Use it, fork it, rip modules out of it.

<div align="center">
<sub><b>Not affiliated with Offensive Security, the Kali project, or any tool vendor listed above.</b><br>
This provisions an analysis environment. What you do with it is on you.</sub>
</div>

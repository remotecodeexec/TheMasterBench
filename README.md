# TheMasterBench

**Set up a Kali Linux workstation for digital forensics and incident response.**

TheMasterBench is a Bash script that installs and configures tools for examining
Windows, macOS, and Linux evidence. It brings disk imaging, file recovery, memory
analysis, log analysis, and reporting tools into one setup process.

It runs on **Kali Linux**. Windows and macOS are sources of evidence you can examine
with the installed tools, not operating systems you run this script on.

## Features

- **Choose what to install:** run all 19 modules or select the ones you need.
- **Cover different investigations:** work with disk images, memory dumps, system
  logs, browser data, email, network captures, and mobile artefacts.
- **Reduce manual setup:** install system packages, download third-party tools,
  and set up isolated Python environments and command wrappers.
- **Organize cases:** create folders for evidence, working files, timelines, and
  reports, with templates for an evidence register and chain of custody.
- **Apply forensic defaults:** configure automount restrictions and a read-only
  rule for removable devices through the `hygiene` module.
- **Track the setup:** keep an installation log, generate a tool inventory, and
  skip modules already marked as completed on later runs.

## Getting started

Use a dedicated Kali Linux machine or VM with internet access, Git, and `sudo`
permissions. Several downloads target x86-64/AMD64; ARM compatibility is not
handled consistently by the script.

```bash
git clone https://github.com/remotecodeexec/TheMasterBench.git
cd TheMasterBench
chmod +x themasterbench.sh
```

Install all modules:

```bash
sudo ./themasterbench.sh --all
```

Or start with a smaller selection:

```bash
sudo ./themasterbench.sh --only core,hygiene,windows,memory
```

The script adds `core` automatically when it is not included in your selection.
Installation time and disk usage depend on the modules and downloads required.

After installation, log out and back in to apply group and command-path changes.
Then check the available tools and review the setup report:

```bash
./themasterbench.sh --verify
cat /opt/themasterbench/MANIFEST.md
```

`--verify` checks whether selected tool commands are on your `PATH`; it does not
test whether those tools work correctly.

## Available modules

These are the tools and capabilities each module attempts to set up. Availability
varies with your Kali release and the upstream projects.

| Module | Purpose and example tools |
| --- | --- |
| `core` | Shared dependencies, build tools, Python, and pipx |
| `hygiene` | Case folders, mount helper, automount restrictions, and user groups |
| `acquisition` | Disk imaging and image formats: dc3dd, ddrescue, Guymager, EWF tools |
| `filesystems` | Filesystem and volume access: NTFS, APFS, LVM, BitLocker, FileVault, and shadow copies |
| `carving` | File recovery: foremost, scalpel, PhotoRec, TestDisk, and binwalk |
| `triage` | Evidence searches, timelines, and hashing: Dissect, Plaso, hashdeep, and YARA |
| `memory` | Memory analysis and acquisition: Volatility 3, MemProcFS, AVML, and LiME source |
| `windows` | Registry, event logs, and filesystem records: RegRipper, Chainsaw, Hayabusa, and MFT parsers |
| `ez_tools` | Eric Zimmerman tools through PowerShell and .NET, where available |
| `macos` | macOS artefacts: mac_apt, unified log parsing, plist tools, and FSEventsParser |
| `linuxart` | Linux logs and system artefacts: audit tools, Sleuth Kit, and Dissect |
| `browsers` | Browser history and SQLite data: Hindsight, sqlite-dissect, and DB Browser for SQLite |
| `email` | Email archives and messages: libpff, readpst, extract-msg, and libratom |
| `malware` | Static analysis: YARA, capa, FLOSS, oletools, and the Didier Stevens suite |
| `network` | Network captures and traffic analysis: Wireshark, tshark, Zeek, and Suricata |
| `mobile` | Mobile artefact parsing: iLEAPP, ALEAPP, and RLEAPP |
| `collection` | Velociraptor for creating evidence collectors |
| `ghidra` | Ghidra reverse engineering, when available in the package repositories |
| `reporting` | Notes and reports: CherryTree, pandoc, and MkDocs |

## Common commands

| Command | What it does |
| --- | --- |
| `./themasterbench.sh --list` | List the available modules |
| `./themasterbench.sh --help` | Show command options |
| `sudo ./themasterbench.sh --all --skip ghidra,mobile` | Install everything except the named modules |
| `sudo ./themasterbench.sh --only windows --force` | Rerun Windows setup and the automatically included core module |
| `./themasterbench.sh --all --dry-run` | Preview setup commands; may still query upstream releases and write logs if permitted |
| `./themasterbench.sh --verify` | Check for tool commands without needing root |

Completed modules are normally skipped. Use `--force` to rerun a module after a
partial installation. It does not guarantee that every installed tool is upgraded.

## Working with cases

The `hygiene` module installs `bench-new-case`:

```bash
bench-new-case CASE-2026-001 "Laptop investigation"
```

This creates `/cases/CASE-2026-001/` with folders for administration, acquisition,
evidence, working files, outputs, tools, and temporary work. The case notes include
an evidence register, a chain-of-custody table, and an activity log for you to fill in.

It also installs `bench-mount-ro`, a helper that attempts to mount an image or device
read-only. Image containers such as E01 need format-specific tools first.

**Use a hardware write blocker for original media.** The software read-only rule
and mount helper are additional precautions, not a replacement.

## Files and folders

| Path | Contents |
| --- | --- |
| `/opt/themasterbench/` | Downloaded repositories, tools, and symbol packs |
| `/opt/themasterbench/MANIFEST.md` | Detected tool paths and versions, plus recorded installation problems |
| `/cases/` | Case working directories |
| `/evidence/` | Intended mount points for evidence |
| `/var/lib/themasterbench/` | Module completion markers |
| `/var/log/themasterbench.log` | Setup log |

## Limitations

- A completed run can still have missing tools. Review the terminal warnings,
  manifest, and log; some failures do not stop a module being marked complete.
- Tool versions are not pinned. Rebuilding later may install different versions.
  Keep a clean VM snapshot and save the manifest alongside your case records.
- Some tools need additional setup, such as building LiME for the target kernel
  or supplying suitable memory symbols. NSRL hash sets and Autopsy 4 are not
  installed by this script.
- Keep case data outside a disposable VM or on a separate persistent disk before
  rebuilding it.

## License

[MIT](LICENSE). Third-party tools retain their own licenses.

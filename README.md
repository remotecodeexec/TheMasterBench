# TheMasterBench

**Set up a Kali Linux workstation for digital forensics and incident response.**

TheMasterBench is a Bash script that installs and configures tools for examining
Windows, macOS, and Linux evidence. It brings disk imaging, file recovery, memory
analysis, log analysis, and reporting tools into one setup process.

It runs on **Kali Linux**. Windows and macOS are sources of evidence you can examine
with the installed tools, not operating systems you run this script on.

## Features

- **Choose what to install:** run all 22 modules or select the ones you need.
- **Build for a purpose:** `--preset lab`, `acquire`, `osint`, or `minimal`.
- **Switch safely at runtime:** `bench-profile` applies an offline, Tor, or
  WireGuard egress profile with a fail-closed killswitch.
- **Keep case data off disk:** RAM-backed scratch, swap disabled, no core dumps,
  and an optional encrypted vault.
- **Cover different investigations:** work with disk images, memory dumps, system
  logs, browser data, email, network captures, mobile artefacts, and OSINT.
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

Or build for a purpose:

```bash
sudo ./themasterbench.sh --preset lab       # offline analysis workstation
sudo ./themasterbench.sh --preset acquire   # imaging and triage
sudo ./themasterbench.sh --preset osint     # OSINT over Tor/VPN
sudo ./themasterbench.sh --preset osint --apply-profile osint-tor
```

`--apply-profile` activates a runtime profile when installation finishes. Every
preset installs all profile definitions, so a box built for one purpose can be
switched to another later. Or select modules explicitly:

```bash
sudo ./themasterbench.sh --only core,hygiene,windows,memory
```

The script adds `core` automatically when it is not included in your selection.
Installation time and disk usage depend on the modules and downloads required.

After installation, log out and back in to apply group and command-path changes.
Then check the available tools, the active profile, and the setup report:

```bash
./themasterbench.sh --verify
sudo bench-profile status
sudo bench-profile test          # IP, Tor, IPv6, DNS leak check
cat /opt/themasterbench/MANIFEST.md
```

`--verify` checks whether selected tool commands and TheMasterBench helpers are
on your `PATH`; it does not test whether those tools work correctly.

## Available modules

These are the tools and capabilities each module attempts to set up. Availability
varies with your Kali release and the upstream projects.

| Module | Purpose and example tools |
| --- | --- |
| `core` | Shared dependencies, build tools, Python, and pipx |
| `hygiene` | Case folders, mount helper, automount restrictions, and user groups |
| `profiles` | Purpose profiles and egress control: nftables killswitch, transparent Tor, WireGuard, `bench-profile` |
| `ephemeral` | RAM-backed `/work`, swap disabled, core dumps off, `bench-scrub` |
| `vault` | LUKS2 case container with a detached header, `bench-vault` |
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
| `network` | Network captures, traffic analysis, and OSINT: Wireshark, tshark, Zeek, Suricata, Maltego, SpiderFoot, Recon-ng, theHarvester, Amass, Subfinder, httpx, Katana, Maigret, Holehe, Tor Browser, AIL Framework, and IntelOwl |
| `mobile` | Mobile artefact parsing: iLEAPP, ALEAPP, and RLEAPP |
| `collection` | Velociraptor for creating evidence collectors |
| `ghidra` | Ghidra reverse engineering, when available in the package repositories |
| `reporting` | Notes and reports: CherryTree, pandoc, and MkDocs |

## Building for a purpose

Presets choose a module set at install time. Every preset includes the `profiles`
module, so the machine can change purpose later without reinstalling.

| Preset | Installs |
| --- | --- |
| `lab` | Everything needed for offline analysis: acquisition, filesystems, carving, triage, memory, Windows/macOS/Linux artefacts, browsers, email, malware, collection, reporting |
| `acquire` | `core`, `hygiene`, `profiles`, `ephemeral`, `acquisition`, `filesystems` |
| `osint` | `core`, `hygiene`, `profiles`, `ephemeral`, `vault`, `browsers`, `network` |
| `minimal` | `core`, `hygiene`, `profiles`, `ephemeral` |

The `lab` and `acquire` presets activate their matching profile when installation
finishes, so the machine is usable in that posture immediately. Override with
`--apply-profile research` if you need network access afterwards (for example,
over SSH). The `osint` preset does not choose between Tor and VPN; pass
`--apply-profile osint-tor` or `osint-vpn`.

At runtime, `bench-profile` switches the network posture:

| Profile | Egress | Use for |
| --- | --- | --- |
| `lab` | none | Evidence analysis. No DNS, updates, or exfiltration path. |
| `acquire` | none, Wi-Fi/Bluetooth blocked | Imaging and live triage |
| `osint-tor` | TCP through Tor, DNS through Tor | OSINT where anonymity matters |
| `osint-vpn` | WireGuard only | OSINT through a known tunnel |
| `research` | unrestricted | Package updates and non-sensitive work |

```bash
sudo bench-profile list
sudo bench-profile use lab --case CASE-2026-001
sudo bench-profile test              # IP, Tor, IPv6, DNS leak check
sudo bench-profile persist on        # apply the saved profile at every boot
sudo bench-profile off               # remove rules, restore normal networking
```

Rules fail closed. If Tor or WireGuard does not come up, egress stays blocked
until you fix it or run `bench-profile off`. The applied profile is written to
`/var/lib/themasterbench/profiles/active` and, when `--case` is given, to the
case's `00_admin/profile.log`.

For `osint-vpn`, copy `/etc/themasterbench/wireguard/osint.conf.example` to
`osint.conf` and fill in your tunnel. The killswitch reads `Endpoint=`, `DNS=`,
and the interface name from that file. The endpoint must resolve over IPv4.

## Common commands

| Command | What it does |
| --- | --- |
| `./themasterbench.sh --list` | List the available modules, presets, and profiles |
| `./themasterbench.sh --help` | Show command options |
| `sudo ./themasterbench.sh --preset osint` | Build an OSINT workstation |
| `sudo ./themasterbench.sh --preset osint --apply-profile osint-tor --case CASE-2026-001` | Build it and start in the Tor profile, recording it in the case |
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

`/work` is RAM-backed scratch for decoders, temporary databases, and exports in
progress. It is wiped on power-off, so it must never hold the only copy of
anything. Finish a session with `sudo bench-scrub` to clear `/work` and shell
history.

The `vault` module installs `bench-vault` for encrypted case storage with a
detached LUKS2 header:

```bash
sudo bench-vault init /evidence/vault.img 50G --keyfile /media/usb/vault.key
sudo bench-vault open /evidence/vault.img /cases
sudo bench-vault close /cases
```

Keep the `.hdr` file and the keyfile on **separate** media from the container.
Losing either one makes the vault unrecoverable. Opening a vault on `/cases`
hides whatever was already in that directory until it is closed.

## Files and folders

| Path | Contents |
| --- | --- |
| `/opt/themasterbench/` | Downloaded repositories, tools, and symbol packs |
| `/opt/themasterbench/MANIFEST.md` | Detected tool paths and versions, plus recorded installation problems |
| `/cases/` | Case working directories |
| `/evidence/` | Intended mount points for evidence |
| `/work/` | RAM-backed scratch (lost on power-off) |
| `/etc/themasterbench/profiles/` | Profile definitions, editable |
| `/etc/themasterbench/wireguard/` | WireGuard config and example |
| `/var/lib/themasterbench/` | Module completion markers and active profile state |
| `/var/log/themasterbench.log` | Setup log |

## Limitations

- A completed run can still have missing tools. Review the terminal warnings,
  manifest, and log; some failures do not stop a module being marked complete.
- Tool versions are not pinned. Rebuilding later may install different versions.
  Keep a clean VM snapshot and save the manifest alongside your case records.
- Some tools need additional setup, such as building LiME for the target kernel,
  supplying suitable memory symbols, or bringing up the Docker-based AIL Framework
  and IntelOwl stacks. Tor Browser downloads its bundle on first launch. NSRL hash
  sets and Autopsy 4 are not installed by this script.
- Keep case data outside a disposable VM or on a separate persistent disk before
  rebuilding it.
- Profiles are software controls, not anonymity guarantees. Tor exit traffic is
  observable, many sources block Tor, and a VPN provider can log. Do not sign in
  to a real identity from an OSINT profile.
- `lab` and `acquire` block **all** egress, including package updates and NTP.
  Apply them before analysis and use `bench-profile off` when you need updates.
  Record the active profile with the case; a box that was online mid-analysis is
  a cross-examination problem.
- Tor does not carry UDP. Scanners that rely on UDP or raw sockets will not work
  through `osint-tor`; the killswitch drops that traffic rather than leaking it.
  Browsers must not be allowed to fall back to QUIC/UDP.
- `/work` is volatile and `/cases` is hidden while a vault is mounted there.
  Copy finished artefacts out of `/work` and close the vault before shutdown.
- Disabling swap protects case data but reduces headroom on low-memory machines.
  If you re-enable it, encrypt the swap device.
- The WireGuard killswitch resolves the endpoint over IPv4 only. IPv6 endpoints
  are not handled and IPv6 egress is not automatically blocked.

## License

[MIT](LICENSE). Third-party tools retain their own licenses.

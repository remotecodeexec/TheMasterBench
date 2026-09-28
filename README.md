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

The easiest way to start is the setup wizard. Run the script with no options:

```bash
sudo ./themasterbench.sh
```

It asks you to choose a starting profile, lets you tick or untick modules, asks
whether to rerun modules that are already complete, and lets you change settings
such as the account to set up and the case folder. It then shows a summary before
anything is installed. The summary includes the equivalent command, so you can
repeat the same setup later without prompts. The wizard uses `whiptail` when it
is available and plain text prompts otherwise.

You can also choose modules with options and skip the wizard. Install all modules:

```bash
sudo ./themasterbench.sh --all
```

Use a predefined profile (see `--list` for what each one includes):

```bash
sudo ./themasterbench.sh --profile windows
```

Or pick the modules yourself:

```bash
sudo ./themasterbench.sh --only core,hygiene,windows,memory
```

Add `-i` to open the wizard with your options already filled in, for example
`sudo ./themasterbench.sh -i --profile memory`. Add `-y` to make sure the script
never prompts. It never prompts when it is not run from a terminal.

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
| `sudo ./themasterbench.sh` | Start the interactive setup wizard |
| `./themasterbench.sh --list` | List the available modules and profiles |
| `./themasterbench.sh --help` | Show command options |
| `sudo ./themasterbench.sh --profile memory` | Install a predefined set of modules |
| `sudo ./themasterbench.sh -i --only windows,memory` | Open the wizard with these modules preselected |
| `sudo ./themasterbench.sh --all --skip ghidra,mobile` | Install everything except the named modules |
| `sudo ./themasterbench.sh --only windows --force` | Rerun Windows setup and the automatically included core module |
| `./themasterbench.sh --all --dry-run` | Preview setup commands; may still query upstream releases and write logs if permitted |
| `./themasterbench.sh --verify` | Check for tool commands without needing root |

Completed modules are normally skipped. Use `--force` to rerun a module after a
partial installation. It does not guarantee that every installed tool is upgraded.

## Settings

These options can also be changed on the wizard's Settings screen:

| Option | Default | What it changes |
| --- | --- | --- |
| `--user NAME` | The account that ran `sudo` | Account that gets the groups, command-line tools and file ownership |
| `--opt-dir DIR` | `/opt/themasterbench` | Folder for downloaded tools, repositories and the manifest |
| `--case-root DIR` | `/cases` | Folder where `bench-new-case` creates cases |
| `--evidence-root DIR` | `/evidence` | Default mount folder for `bench-mount-ro` |
| `--no-udev-ro` | Rule installed | Don't force removable disks read-only |
| `--no-polkit` | Rule installed | Don't require an admin password to mount removable media |

The last four apply to the `hygiene` module. If an earlier run installed a rule,
`--no-udev-ro` or `--no-polkit` removes it; `--udev-ro` and `--polkit` turn a
rule back on.

### Saved settings

After each run (except dry runs) the settings above are saved to
`~/.config/themasterbench/settings.conf`, in the home folder of the account that
ran `sudo`, and the next run starts from them. You don't have to repeat your
options, and a rerun of `hygiene` keeps the same folders:

```bash
sudo ./themasterbench.sh --only hygiene --case-root /srv/cases   # saves /srv/cases
sudo ./themasterbench.sh --only hygiene --force                   # still uses /srv/cases
```

Options on the command line override saved values, and the wizard shows the saved
values as its starting point. The file is plain `key=value` lines:

```ini
user=kali
opt_dir=/opt/themasterbench
case_root=/srv/cases
evidence_root=/evidence
udev_ro=1
polkit_rule=1
```

Delete the file to go back to the defaults. Use `--config FILE` to load and save a
different file, for example one kept with your VM build notes, or `--no-config`
to ignore saved settings for one run. The script reads the file as data (it is
never run as a script) and rejects invalid values.

## Working with cases

The `hygiene` module installs `bench-new-case`:

```bash
bench-new-case CASE-2026-001 "Laptop investigation"
```

This creates `/cases/CASE-2026-001/` (or the folder set with `--case-root`) with folders for administration, acquisition,
evidence, working files, outputs, tools, and temporary work. The case notes include
an evidence register, a chain-of-custody table, and an activity log for you to fill in.

It also installs `bench-mount-ro`, a helper that attempts to mount an image or device
read-only. Image containers such as E01 need format-specific tools first.

**Use a hardware write blocker for original media.** The software read-only rule
and mount helper are additional precautions, not a replacement.

## Files and folders

| Path | Contents |
| --- | --- |
| `/opt/themasterbench/` | Downloaded repositories, tools, and symbol packs (`--opt-dir`) |
| `/opt/themasterbench/MANIFEST.md` | Detected tool paths and versions, plus recorded installation problems |
| `/cases/` | Case working directories (`--case-root`) |
| `/evidence/` | Intended mount points for evidence (`--evidence-root`) |
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

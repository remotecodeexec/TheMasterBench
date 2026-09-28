#!/usr/bin/env bash
#===============================================================================
# themasterbench.sh  --  TheMasterBench
#
# Provision a Kali Linux box into a cross-platform (Windows / macOS / Linux)
# digital-forensics workstation.
#
# Design goals:
#   * Idempotent      - safe to run repeatedly; skips what is already done.
#   * Rebuildable     - one command restores a destroyed VM to a known state.
#   * Non-fatal       - a missing upstream package never aborts the whole run.
#   * Auditable       - every action logged, every tool recorded in a manifest.
#
# Usage:
#   sudo ./themasterbench.sh --all
#   sudo ./themasterbench.sh --only core,windows,memory
#   sudo ./themasterbench.sh --all --skip ghidra,mobile
#   sudo ./themasterbench.sh --list
#   ./themasterbench.sh --verify          # no root needed
#
#===============================================================================
set -Eeuo pipefail

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

#--- Paths --------------------------------------------------------------------
# OPT_DIR, CASE_ROOT and EVIDENCE_ROOT can be changed with --opt-dir,
# --case-root and --evidence-root, or in the wizard.
DEFAULT_OPT_DIR="/opt/themasterbench"
DEFAULT_CASE_ROOT="/cases"
DEFAULT_EVIDENCE_ROOT="/evidence"
OPT_DIR="$DEFAULT_OPT_DIR"              # third-party tools cloned/unpacked here
STATE_DIR="/var/lib/themasterbench"     # per-module completion markers
LOG_FILE="/var/log/themasterbench.log"  # provisioning log
CASE_ROOT="$DEFAULT_CASE_ROOT"          # working case data
EVIDENCE_ROOT="$DEFAULT_EVIDENCE_ROOT"  # mount point for read-only source media
MANIFEST="${OPT_DIR}/MANIFEST.md"       # recomputed once OPT_DIR is final

#--- Runtime flags ------------------------------------------------------------
DRY_RUN=0
FORCE=0
INTERACTIVE=auto      # auto | 1 (--interactive) | 0 (--yes: never prompt)
PROFILE=""
UDEV_RO=1             # hygiene: udev rule forcing removable disks read-only (--no-udev-ro)
POLKIT_RULE=1         # hygiene: admin auth for mounting removable media (--no-polkit)
declare -A SET_BY_FLAG=()   # options given on the command line; the wizard won't re-ask
declare -a SELECTED=()
declare -a SKIPPED=()
declare -a MISSING_PKGS=()
declare -a FAILED_STEPS=()

#--- Target user (the human, not root) ----------------------------------------
TARGET_USER="${SUDO_USER:-${USER:-root}}"
[[ "$TARGET_USER" == "root" && -n "${SUDO_USER:-}" ]] && TARGET_USER="$SUDO_USER"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
TARGET_HOME="${TARGET_HOME:-/root}"
DEFAULT_TARGET_USER="$TARGET_USER"      # --user or the wizard can change it
DEFAULT_TARGET_HOME="$TARGET_HOME"

#--- Saved settings (see load_settings) ---------------------------------------
DEFAULT_CONFIG_FILE="${DEFAULT_TARGET_HOME}/.config/themasterbench/settings.conf"
CONFIG_FILE="$DEFAULT_CONFIG_FILE"      # --config FILE; empty with --no-config
CONFIG_LOADED=0

#===============================================================================
# Module registry  (order matters: 'core' first)
#===============================================================================
declare -a ALL_MODULES=(
  core            # build deps, pipx, python, helpers
  hygiene         # automount off, groups, case tree, evidence mount helper
  acquisition     # imaging + image format handling
  filesystems     # FS drivers, volume/container handling (BitLocker, FileVault, APFS, LVM, VSS)
  carving         # file carving + data recovery
  triage          # dissect, plaso, timelines, hashing
  memory          # Volatility 3, MemProcFS, AVML, LiME
  windows         # registry, EVTX, MFT, prefetch, jumplists, SRUM, Amcache
  ez_tools        # Eric Zimmerman .NET toolset (best-effort)
  macos           # APFS, unified logs, plists, mac_apt
  linuxart        # Linux host artefacts
  browsers        # browser + SQLite forensics
  email           # PST/OST/MSG/mbox
  malware         # static analysis / YARA / capa / unpackers
  network         # pcap + network forensics
  mobile          # iLEAPP / ALEAPP / RLEAPP
  collection      # Velociraptor offline collectors
  ghidra          # heavy RE suite (optional)
  reporting       # notes, case templating, report helpers
)

declare -A MODULE_DESC=(
  [core]="Build toolchain, Python/pipx, common utilities"
  [hygiene]="Forensic hygiene: disable automount, groups, /cases + /evidence tree"
  [acquisition]="dc3dd, ewf-tools, guymager, ddrescue, image format mounters"
  [filesystems]="NTFS/exFAT/HFS+/APFS/ext, LVM, BitLocker, FileVault, VSS, VHD/VMDK/QCOW"
  [carving]="foremost, scalpel, bulk_extractor, photorec, binwalk, recovery tools"
  [triage]="dissect, plaso/log2timeline, sleuthkit, hashdeep/ssdeep, yara"
  [memory]="Volatility 3, MemProcFS, AVML, LiME, memory acquisition helpers"
  [windows]="RegRipper, regipy, evtx tools, chainsaw, hayabusa, MFT/INDX/SRUM parsers"
  [ez_tools]="Eric Zimmerman .NET tools via PowerShell (best-effort)"
  [macos]="apfs-fuse, unified log parser, plist tools, mac_apt"
  [linuxart]="utmp/wtmp, journald, auditd, package + persistence artefact tooling"
  [browsers]="Hindsight, SQLite forensics, cache/history parsers"
  [email]="libpff (PST/OST), readpst, extract-msg, mbox tooling"
  [malware]="YARA, capa, FLOSS, oletools, Didier Stevens suite, ClamAV, DIE"
  [network]="Wireshark/tshark, NetworkMiner deps, zeek/suricata, pcap tooling"
  [mobile]="iLEAPP / ALEAPP / RLEAPP artefact parsers"
  [collection]="Velociraptor binary + offline collector workflow"
  [ghidra]="Ghidra reverse-engineering suite (large download)"
  [reporting]="Case scaffolding, note-taking, report helpers"
)

#--- Profiles: named module sets (keep modules in ALL_MODULES order) ----------
declare -a PROFILE_ORDER=(full windows macos linux memory malware minimal)
declare -A PROFILE_MODULES=(
  [full]="${ALL_MODULES[*]}"
  [windows]="core hygiene acquisition filesystems carving triage memory windows ez_tools browsers email reporting"
  [macos]="core hygiene acquisition filesystems carving triage macos browsers reporting"
  [linux]="core hygiene acquisition filesystems carving triage memory linuxart reporting"
  [memory]="core hygiene triage memory reporting"
  [malware]="core hygiene triage malware network ghidra reporting"
  [minimal]="core hygiene acquisition triage reporting"
)
declare -A PROFILE_DESC=(
  [full]="Every module"
  [windows]="Windows host investigations"
  [macos]="macOS host investigations"
  [linux]="Linux host investigations"
  [memory]="Memory analysis"
  [malware]="Malware and network analysis, reverse engineering"
  [minimal]="Imaging, triage and case tooling only"
)

#===============================================================================
# Logging helpers
#===============================================================================
C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'
C_YLW=$'\033[33m'; C_BLU=$'\033[34m'; C_DIM=$'\033[2m'
[[ -t 1 ]] || { C_RESET=""; C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_DIM=""; }

_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

_log_raw() {
  local line="$1"
  if [[ -w "$(dirname "$LOG_FILE")" || -w "$LOG_FILE" ]] 2>/dev/null; then
    printf '%s %s\n' "$(_ts)" "$line" >> "$LOG_FILE" 2>/dev/null || true
  fi
}

log()  { printf '%s[*]%s %s\n' "$C_BLU" "$C_RESET" "$*"; _log_raw "[INFO] $*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_RESET" "$*"; _log_raw "[ OK ] $*"; }
warn() { printf '%s[!]%s %s\n' "$C_YLW" "$C_RESET" "$*" >&2; _log_raw "[WARN] $*"; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; _log_raw "[FAIL] $*"; }
die()  { err "$*"; exit 1; }
hdr()  {
  printf '\n%s===============================================================%s\n' "$C_BLU" "$C_RESET"
  printf '%s  %s%s\n' "$C_BLU" "$*" "$C_RESET"
  printf '%s===============================================================%s\n' "$C_BLU" "$C_RESET"
  _log_raw "[STEP] === $* ==="
}

on_error() {
  local exit_code=$? line=${BASH_LINENO[0]}
  err "Unhandled error (exit ${exit_code}) near line ${line} of ${SCRIPT_NAME}."
  err "See ${LOG_FILE} for the full trace."
  exit "$exit_code"
}
trap on_error ERR

#===============================================================================
# Primitives
#===============================================================================
have()      { command -v "$1" >/dev/null 2>&1; }
is_root()   { [[ "$(id -u)" -eq 0 ]]; }

run() {
  if (( DRY_RUN )); then
    printf '%s    DRY-RUN:%s %s\n' "$C_DIM" "$C_RESET" "$*"
    return 0
  fi
  _log_raw "[EXEC] $*"
  "$@"
}

# Run a command as the non-root user, with a login-ish environment.
as_user() {
  if (( DRY_RUN )); then
    printf '%s    DRY-RUN (as %s):%s %s\n' "$C_DIM" "$TARGET_USER" "$C_RESET" "$*"
    return 0
  fi
  _log_raw "[EXEC as ${TARGET_USER}] $*"
  if [[ "$TARGET_USER" == "root" ]]; then
    "$@"
  else
    sudo -u "$TARGET_USER" -H env "HOME=$TARGET_HOME" \
      "PATH=${TARGET_HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin" "$@"
  fi
}

mark_done()    { (( DRY_RUN )) || { mkdir -p "$STATE_DIR"; : > "${STATE_DIR}/$1.done"; }; }
already_done() { (( FORCE )) && return 1; [[ -f "${STATE_DIR}/$1.done" ]]; }

record_failure() { FAILED_STEPS+=("$1"); warn "Step failed (continuing): $1"; }

#------------------------------------------------------------------------------
# apt: install packages ONE AT A TIME so a single renamed/dropped package
# cannot abort the whole module. Missing names are collected and reported.
#------------------------------------------------------------------------------
APT_UPDATED=0
apt_refresh() {
  (( APT_UPDATED )) && return 0
  log "Refreshing apt package lists"
  run apt-get update -qq || warn "apt-get update reported errors; continuing"
  APT_UPDATED=1
}

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }
pkg_exists()    { apt-cache show "$1" >/dev/null 2>&1; }

apt_install() {
  apt_refresh
  local pkg
  for pkg in "$@"; do
    if pkg_installed "$pkg"; then
      printf '%s    already installed: %s%s\n' "$C_DIM" "$pkg" "$C_RESET"
      continue
    fi
    if ! pkg_exists "$pkg"; then
      MISSING_PKGS+=("$pkg")
      warn "Not in repositories on this release: ${pkg}"
      continue
    fi
    log "apt install ${pkg}"
    if ! run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
           -o Dpkg::Options::=--force-confold "$pkg"; then
      MISSING_PKGS+=("$pkg (install failed)")
      warn "Failed to install ${pkg}"
    fi
  done
}

#------------------------------------------------------------------------------
# pipx: isolated Python tools, owned by the target user (avoids PEP-668 pain)
#------------------------------------------------------------------------------
pipx_install() {
  local spec name
  for spec in "$@"; do
    name="${spec%%[<>=\[]*}"
    if as_user pipx list --short 2>/dev/null | awk '{print $1}' | grep -qx "$name"; then
      printf '%s    pipx already: %s%s\n' "$C_DIM" "$name" "$C_RESET"
      continue
    fi
    log "pipx install ${spec}"
    as_user pipx install --pip-args=--quiet "$spec" \
      || record_failure "pipx install ${spec}"
  done
}

pipx_inject() {  # pipx_inject <app> <pkg> [pkg...]
  local app="$1"; shift
  log "pipx inject into ${app}: $*"
  as_user pipx inject --pip-args=--quiet "$app" "$@" || record_failure "pipx inject ${app}"
}

#------------------------------------------------------------------------------
# git: clone or update into /opt/themasterbench, owned by target user
#------------------------------------------------------------------------------
git_sync() {  # git_sync <url> <dirname> [branch]
  local url="$1" name="$2" branch="${3:-}" dest="${OPT_DIR}/${2}"
  run mkdir -p "$OPT_DIR"
  if [[ -d "${dest}/.git" ]]; then
    log "Updating ${name}"
    run git -C "$dest" fetch --quiet --depth 1 origin || { record_failure "git fetch ${name}"; return 0; }
    run git -C "$dest" reset --quiet --hard "origin/$(git -C "$dest" symbolic-ref --short HEAD 2>/dev/null || echo main)" 2>/dev/null || true
  else
    log "Cloning ${name}"
    if [[ -n "$branch" ]]; then
      run git clone --quiet --depth 1 --branch "$branch" "$url" "$dest" || { record_failure "git clone ${name}"; return 0; }
    else
      run git clone --quiet --depth 1 "$url" "$dest" || { record_failure "git clone ${name}"; return 0; }
    fi
  fi
  (( DRY_RUN )) || chown -R "${TARGET_USER}:${TARGET_USER}" "$dest" 2>/dev/null || true
}

# Create a dedicated venv for a cloned repo and expose its entrypoint on PATH.
venv_from_repo() {  # venv_from_repo <dirname> <entry_script> <wrapper_name>
  local name="$1" entry="$2" wrapper="$3"
  local dest="${OPT_DIR}/${name}" venv="${OPT_DIR}/${name}/.venv"
  [[ -d "$dest" ]] || return 0
  if [[ ! -x "${venv}/bin/python" ]]; then
    log "Creating venv for ${name}"
    run python3 -m venv "$venv" || { record_failure "venv ${name}"; return 0; }
  fi
  run "${venv}/bin/pip" install --quiet --upgrade pip wheel || true
  if [[ -f "${dest}/requirements.txt" ]]; then
    run "${venv}/bin/pip" install --quiet -r "${dest}/requirements.txt" \
      || record_failure "pip requirements for ${name}"
  fi
  (( DRY_RUN )) && return 0
  cat > "/usr/local/bin/${wrapper}" <<EOF
#!/usr/bin/env bash
exec "${venv}/bin/python" "${dest}/${entry}" "\$@"
EOF
  chmod 0755 "/usr/local/bin/${wrapper}"
  ok "Wrapper installed: ${wrapper}"
}

#------------------------------------------------------------------------------
# GitHub release downloader (asset name matched by a grep pattern)
#------------------------------------------------------------------------------
gh_release_asset() {  # gh_release_asset <owner/repo> <grep-pattern> <outfile>
  local repo="$1" pattern="$2" out="$3" api url
  api="https://api.github.com/repos/${repo}/releases/latest"
  url="$(curl -fsSL "$api" 2>/dev/null \
        | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | cut -d'"' -f4 | grep -E "$pattern" | head -n1 || true)"
  if [[ -z "$url" ]]; then
    warn "No release asset matching '${pattern}' for ${repo}"
    return 1
  fi
  log "Downloading ${url##*/} from ${repo}"
  run curl -fsSL --retry 3 --retry-delay 2 -o "$out" "$url"
}

#===============================================================================
# MODULES
#===============================================================================

module_core() {
  hdr "core - toolchain, Python, helpers"
  apt_install \
    build-essential cmake pkg-config git curl wget ca-certificates gnupg \
    unzip p7zip-full zstd xz-utils bzip2 jq ripgrep fd-find tree \
    python3 python3-dev python3-venv python3-pip pipx \
    libssl-dev zlib1g-dev libbz2-dev libffi-dev libsqlite3-dev \
    libfuse3-dev fuse3 uuid-dev libz-dev libattr1-dev \
    default-jre-headless mono-runtime tmux vim less rsync parallel \
    sqlite3 xmlstarlet bsdextrautils
  run mkdir -p "$OPT_DIR" "$STATE_DIR"
  (( DRY_RUN )) || chown -R "${TARGET_USER}:${TARGET_USER}" "$OPT_DIR" 2>/dev/null || true
  as_user pipx ensurepath >/dev/null 2>&1 || true
  ok "core ready"
}

POLKIT_RULE_FILE="/etc/polkit-1/rules.d/10-themasterbench-no-automount.rules"
UDEV_RO_FILE="/etc/udev/rules.d/99-themasterbench-removable-ro.rules"

# drop_rule <file> <what> -- remove a rule an earlier run installed.
drop_rule() {
  [[ -f "$1" ]] || { log "Not installing $2"; return 0; }
  run rm -f "$1"
  ok "Removed $2: $1"
}

module_hygiene() {
  hdr "hygiene - forensic defaults, groups, case tree"

  # 1. Case + evidence directory structure
  run mkdir -p "${CASE_ROOT}" "${EVIDENCE_ROOT}"
  run mkdir -p "${CASE_ROOT}/.templates"
  (( DRY_RUN )) || chown -R "${TARGET_USER}:${TARGET_USER}" "$CASE_ROOT" 2>/dev/null || true

  # 2. Kill desktop auto-mounting so plugging in evidence does not touch it
  if have gsettings && [[ "$TARGET_USER" != "root" ]]; then
    log "Disabling GNOME automount for ${TARGET_USER}"
    as_user gsettings set org.gnome.desktop.media-handling automount false      2>/dev/null || true
    as_user gsettings set org.gnome.desktop.media-handling automount-open false 2>/dev/null || true
    as_user gsettings set org.gnome.desktop.media-handling autorun-never true   2>/dev/null || true
  fi
  if (( ! POLKIT_RULE )); then
    drop_rule "$POLKIT_RULE_FILE" "polkit mount rule (--no-polkit)"
  elif [[ -d /etc/udisks2 ]] || pkg_installed udisks2; then
    (( DRY_RUN )) || {
      mkdir -p /etc/polkit-1/rules.d
      cat > "$POLKIT_RULE_FILE" <<'EOF'
// TheMasterBench: deny unprivileged filesystem mounting of removable media.
// Evidence is mounted deliberately, read-only, by the examiner.
polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.udisks2.filesystem-mount" ||
      action.id == "org.freedesktop.udisks2.filesystem-mount-system") {
    return polkit.Result.AUTH_ADMIN;
  }
});
EOF
    }
    ok "udisks2 mount actions now require admin auth"
  fi

  # 3. Optional: force removable block devices read-only at the kernel level.
  #    NOT a replacement for a hardware write blocker - it is a second net.
  if (( ! UDEV_RO )); then
    drop_rule "$UDEV_RO_FILE" "udev read-only rule (--no-udev-ro)"
  else
    (( DRY_RUN )) || cat > "$UDEV_RO_FILE" <<'EOF'
# TheMasterBench - force newly attached removable block devices read-only.
# This is a software safety net, NOT a substitute for a hardware write blocker.
# Comment this file out (or `blockdev --setrw`) when you deliberately need write access.
ACTION=="add", KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{removable}=="1", \
  RUN+="/sbin/blockdev --setro /dev/%k"
ACTION=="add", KERNEL=="sd[a-z][0-9]", SUBSYSTEM=="block", \
  RUN+="/bin/sh -c '[ \"$(cat /sys/block/$(echo %k | sed \"s/[0-9]*$//\")/removable 2>/dev/null)\" = 1 ] && /sbin/blockdev --setro /dev/%k || true'"
EOF
    ok "udev read-only rule installed (${UDEV_RO_FILE##*/})"
  fi
  run udevadm control --reload-rules 2>/dev/null || true

  # 4. Groups the examiner needs
  local g
  for g in disk fuse wireshark vboxsf kvm; do
    getent group "$g" >/dev/null 2>&1 || continue
    id -nG "$TARGET_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$g" && continue
    log "Adding ${TARGET_USER} to group ${g}"
    run usermod -aG "$g" "$TARGET_USER" || true
  done

  # 5. Helper: mount an image or device read-only, the boring safe way
  (( DRY_RUN )) || {
    cat > /usr/local/bin/bench-mount-ro <<'EOF'
#!/usr/bin/env bash
# bench-mount-ro <image-or-device> [mountpoint] [--offset BYTES]
# Mounts read-only with no atime updates and no journal replay.
set -euo pipefail
SRC="${1:?usage: bench-mount-ro <image|device> [mountpoint] [--offset BYTES]}"
MNT="${2:-@EVIDENCE_ROOT@/$(basename "$SRC" | tr -c 'A-Za-z0-9._-' '_')}"
OFFSET=""
[[ "${3:-}" == "--offset" ]] && OFFSET=",offset=${4:?offset value}"
mkdir -p "$MNT"
OPTS="ro,noexec,nodev,noatime,noload,loop,show_sys_files,streams_interface=windows${OFFSET}"
echo "[*] mounting $SRC -> $MNT (read-only)"
if ! mount -o "$OPTS" "$SRC" "$MNT" 2>/dev/null; then
  # fall back for filesystems that reject NTFS/ext-specific options
  mount -o "ro,noexec,nodev,noatime,loop${OFFSET}" "$SRC" "$MNT"
fi
echo "[+] mounted read-only at $MNT"
mount | grep -F "$MNT"
EOF
    chmod 0755 /usr/local/bin/bench-mount-ro

    cat > /usr/local/bin/bench-new-case <<'EOF'
#!/usr/bin/env bash
# bench-new-case <case-id> [description]
set -euo pipefail
CASE_ID="${1:?usage: bench-new-case <case-id> [description]}"
DESC="${2:-}"
ROOT="@CASE_ROOT@/${CASE_ID}"
[[ -e "$ROOT" ]] && { echo "Case already exists: $ROOT" >&2; exit 1; }
mkdir -p "$ROOT"/{00_admin,01_acquisition,02_evidence,03_working,04_output/{timelines,reports,exports},05_tools,99_scratch}
cat > "$ROOT/00_admin/case.md" <<META
# Case ${CASE_ID}

- Opened (UTC): $(date -u '+%Y-%m-%d %H:%M:%SZ')
- Examiner: $(id -un)@$(hostname)
- Description: ${DESC}

## Evidence register

| Item | Source | Acquired (UTC) | Acquisition hash | Verified | Notes |
|------|--------|----------------|------------------|----------|-------|
|      |        |                |                  |          |       |

## Chain of custody

| When (UTC) | Who | Action | Notes |
|------------|-----|--------|-------|
|            |     |        |       |

## Activity log
META
: > "$ROOT/00_admin/commands.log"
chmod -R u+rwX "$ROOT"
echo "[+] Created $ROOT"
tree -L 2 "$ROOT" 2>/dev/null || find "$ROOT" -maxdepth 2
EOF
    chmod 0755 /usr/local/bin/bench-new-case
    # Paths are validated to [A-Za-z0-9._/-], so they are safe in sed.
    sed -i -e "s|@CASE_ROOT@|${CASE_ROOT}|g" -e "s|@EVIDENCE_ROOT@|${EVIDENCE_ROOT}|g" \
      /usr/local/bin/bench-mount-ro /usr/local/bin/bench-new-case
  }
  ok "helpers installed: bench-mount-ro, bench-new-case"
}

module_acquisition() {
  hdr "acquisition - imaging and image formats"
  apt_install \
    dc3dd dcfldd gddrescue safecopy guymager \
    ewf-tools libewf-dev afflib-tools xmount \
    libvhdi-utils libqcow-utils libvmdk-utils libvslvm-utils \
    sleuthkit disktype hdparm sdparm smartmontools nvme-cli \
    gdisk parted fdisk dosfstools mtools udftools
  ok "acquisition tooling in place"
}

module_filesystems() {
  hdr "filesystems - volumes, containers, encryption"
  apt_install \
    ntfs-3g exfatprogs exfat-fuse hfsprogs hfsutils jfsutils xfsprogs btrfs-progs \
    f2fs-tools reiserfsprogs squashfs-tools cryptsetup cryptsetup-bin lvm2 mdadm \
    libbde-utils libfvde-utils libfsapfs-utils libfsntfs-utils libfsext-utils \
    libfshfs-utils libfsxfs-utils libvshadow-utils libluksde-utils \
    libmodi-utils libphdi-utils

  # apfs-fuse is rarely packaged; build it when absent.
  if ! have apfs-fuse; then
    log "Building apfs-fuse from source (macOS APFS read support)"
    apt_install libbz2-dev libattr1-dev zlib1g-dev libfuse3-dev cmake g++ libplist-dev
    git_sync "https://github.com/sgan81/apfs-fuse.git" "apfs-fuse"
    if [[ -d "${OPT_DIR}/apfs-fuse" ]] && (( ! DRY_RUN )); then
      (
        cd "${OPT_DIR}/apfs-fuse"
        git submodule update --init --recursive --depth 1 >/dev/null 2>&1 || true
        mkdir -p build && cd build
        cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1 \
          && make -j"$(nproc)" >/dev/null 2>&1 \
          && install -m0755 apfs-fuse apfsutil /usr/local/bin/ 2>/dev/null
      ) || record_failure "apfs-fuse build"
      have apfs-fuse && ok "apfs-fuse built and installed"
    fi
  else
    ok "apfs-fuse already present"
  fi
}

module_carving() {
  hdr "carving - recovery and file carving"
  apt_install \
    foremost scalpel bulk-extractor testdisk binwalk \
    recoverjpeg extundelete ext4magic scrounge-ntfs \
    magicrescue myrescue sleuthkit
  pipx_install "binwalk"
  ok "carving tooling in place"
}

module_triage() {
  hdr "triage - dissect, timelines, hashing, YARA"
  apt_install \
    plaso python3-plaso hashdeep ssdeep sdhash yara libimage-exiftool-perl \
    mac-robber pev unrar-free cabextract
  # dissect (fox-it): one framework that speaks Windows, Linux and macOS images.
  pipx_install "dissect"
  pipx_install "dissect.target[full]" || true
  # Timeline tooling
  pipx_install "timesketch-import-client"
  ok "triage tooling in place"
  log "Key entrypoints: target-query, target-fs, target-shell, acquire, log2timeline.py, psort.py"
}

module_memory() {
  hdr "memory - acquisition and analysis"
  apt_install volatility3 python3-yara

  have vol || have volatility3 || pipx_install "volatility3"

  # Symbol tables for Windows/macOS/Linux profiles
  run mkdir -p "${OPT_DIR}/volatility-symbols"
  local sym
  for sym in windows mac linux; do
    if [[ ! -f "${OPT_DIR}/volatility-symbols/${sym}.zip" ]]; then
      run curl -fsSL --retry 3 -o "${OPT_DIR}/volatility-symbols/${sym}.zip" \
        "https://downloads.volatilityfoundation.org/volatility3/symbols/${sym}.zip" \
        || warn "Could not fetch ${sym} symbol pack (fetch manually later)"
    fi
  done

  # MemProcFS - mount a memory image as a filesystem
  if [[ ! -x "${OPT_DIR}/memprocfs/memprocfs" ]]; then
    run mkdir -p "${OPT_DIR}/memprocfs"
    if gh_release_asset "ufrisk/MemProcFS" "linux.*\.tar\.gz$" "/tmp/memprocfs.tar.gz"; then
      run tar -xzf /tmp/memprocfs.tar.gz -C "${OPT_DIR}/memprocfs" || record_failure "memprocfs extract"
      (( DRY_RUN )) || {
        find "${OPT_DIR}/memprocfs" -name memprocfs -type f -exec chmod +x {} \; 2>/dev/null || true
        local mpf; mpf="$(find "${OPT_DIR}/memprocfs" -name memprocfs -type f | head -n1)"
        [[ -n "$mpf" ]] && ln -sf "$mpf" /usr/local/bin/memprocfs
      }
      ok "MemProcFS installed"
    fi
  fi

  # AVML - Microsoft's Linux memory acquisition binary
  if [[ ! -x /usr/local/bin/avml ]]; then
    if gh_release_asset "microsoft/avml" "avml$" "/tmp/avml"; then
      run install -m0755 /tmp/avml /usr/local/bin/avml && ok "AVML installed"
    fi
  fi

  # LiME kernel module source (build per target kernel at acquisition time)
  git_sync "https://github.com/504ensicsLabs/LiME.git" "LiME"
  ok "memory tooling in place"
}

module_windows() {
  hdr "windows - registry, event logs, MFT, execution artefacts"
  apt_install \
    libregf-utils libevtx-utils libevt-utils libesedb-utils liblnk-utils \
    libscca-utils libolecf-utils libmsiecf-utils libpff-tools libsigscan-utils \
    libcreg-utils libwrc-utils registry-tools regripper pasco galleta rifiuti2 \
    chainsaw hayabusa

  pipx_install \
    "regipy[cli]" \
    "python-registry" \
    "analyzeMFT" \
    "dfir-ntfs" \
    "INDXRipper" \
    "sigma-cli" \
    "libesedb-python" || true

  # RegRipper 3 (current plugin set), on top of the packaged version
  git_sync "https://github.com/keydet89/RegRipper3.0.git" "RegRipper3.0"

  # evtx_dump (Rust) if the apt package did not provide one
  if ! have evtx_dump; then
    if gh_release_asset "omerbenamram/evtx" "evtx_dump-.*linux-gnu$|evtx_dump-.*x86_64-unknown-linux-gnu$" "/tmp/evtx_dump"; then
      run install -m0755 /tmp/evtx_dump /usr/local/bin/evtx_dump && ok "evtx_dump installed"
    fi
  fi

  # chainsaw / hayabusa fallbacks when not packaged
  if ! have chainsaw; then
    run mkdir -p "${OPT_DIR}/chainsaw"
    if gh_release_asset "WithSecureLabs/chainsaw" "unknown-linux-gnu.*\.tar\.gz$|linux.*\.zip$" "/tmp/chainsaw.pkg"; then
      (( DRY_RUN )) || {
        case "$(file -b --mime-type /tmp/chainsaw.pkg 2>/dev/null)" in
          application/zip) unzip -oq /tmp/chainsaw.pkg -d "${OPT_DIR}/chainsaw" ;;
          *)               tar -xzf /tmp/chainsaw.pkg -C "${OPT_DIR}/chainsaw" ;;
        esac
        local cs; cs="$(find "${OPT_DIR}/chainsaw" -name 'chainsaw*' -type f -perm -u+x | head -n1)"
        [[ -n "$cs" ]] && { chmod +x "$cs"; ln -sf "$cs" /usr/local/bin/chainsaw; ok "chainsaw installed"; }
      }
    fi
  fi

  # Sigma + EVTX-ATTACK-SAMPLES style rule sets for detection engineering
  git_sync "https://github.com/SigmaHQ/sigma.git" "sigma"
  ok "Windows artefact tooling in place"
}

module_ez_tools() {
  hdr "ez_tools - Eric Zimmerman .NET suite (best-effort)"
  apt_install powershell dotnet-runtime-8.0 dotnet-sdk-8.0 || true
  if ! have pwsh; then
    warn "PowerShell not available from apt on this release."
    warn "Install manually from https://github.com/PowerShell/PowerShell/releases, then re-run: ${SCRIPT_NAME} --only ez_tools"
    return 0
  fi
  run mkdir -p "${OPT_DIR}/ZimmermanTools"
  log "Fetching Get-ZimmermanTools.ps1"
  if run curl -fsSL -o "${OPT_DIR}/ZimmermanTools/Get-ZimmermanTools.ps1" \
        "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"; then
    (( DRY_RUN )) || (
      cd "${OPT_DIR}/ZimmermanTools"
      pwsh -NoProfile -ExecutionPolicy Bypass -File ./Get-ZimmermanTools.ps1 -Dest . -NetVersion 8 >/dev/null 2>&1
    ) || record_failure "Get-ZimmermanTools"
    (( DRY_RUN )) || {
      # Wrap the cross-platform CLI tools so they are on PATH
      local t dll
      for t in MFTECmd PECmd LECmd JLECmd RECmd SBECmd AmcacheParser EvtxECmd SrumECmd RBCmd WxTCmd bstrings; do
        dll="$(find "${OPT_DIR}/ZimmermanTools" -name "${t}.dll" -o -name "${t}" -type f 2>/dev/null | head -n1)"
        [[ -z "$dll" ]] && continue
        if [[ "$dll" == *.dll ]]; then
          printf '#!/usr/bin/env bash\nexec dotnet "%s" "$@"\n' "$dll" > "/usr/local/bin/${t,,}"
        else
          printf '#!/usr/bin/env bash\nexec "%s" "$@"\n' "$dll" > "/usr/local/bin/${t,,}"
        fi
        chmod 0755 "/usr/local/bin/${t,,}"
      done
      ok "Zimmerman CLI wrappers installed (lowercase names, e.g. 'mftecmd')"
    }
  else
    warn "Could not fetch Get-ZimmermanTools.ps1"
  fi
}

module_macos() {
  hdr "macos - APFS, unified logs, plists"
  apt_install libplist-utils libimobiledevice-utils libfvde-utils libfsapfs-utils \
              libmodi-utils sqlite3

  # mac_apt - the broadest macOS artefact parser
  git_sync "https://github.com/ydkhatri/mac_apt.git" "mac_apt"
  venv_from_repo "mac_apt" "mac_apt.py" "mac-apt"

  # Unified logs (.tracev3) parser - Rust
  if ! have unifiedlog_parser; then
    apt_install cargo rustc
    if have cargo; then
      git_sync "https://github.com/mandiant/macos-UnifiedLogs.git" "macos-UnifiedLogs"
      if [[ -d "${OPT_DIR}/macos-UnifiedLogs/examples/unifiedlog_parser" ]] && (( ! DRY_RUN )); then
        ( cd "${OPT_DIR}/macos-UnifiedLogs/examples/unifiedlog_parser" \
          && cargo build --release >/dev/null 2>&1 \
          && install -m0755 target/release/unifiedlog_parser /usr/local/bin/ ) \
          || record_failure "unifiedlog_parser build"
        have unifiedlog_parser && ok "unifiedlog_parser installed"
      fi
    fi
  fi

  # FSEvents
  git_sync "https://github.com/dlcowen/FSEventsParser.git" "FSEventsParser"
  pipx_install "ccl-bplist" || true
  ok "macOS artefact tooling in place"
}

module_linuxart() {
  hdr "linuxart - Linux host artefacts"
  apt_install \
    acct auditd systemd-coredump debsums rkhunter chkrootkit \
    lsof psmisc net-tools iproute2 strace ltrace \
    libewf-dev sleuthkit
  pipx_install "dissect.target" || true
  git_sync "https://github.com/ashemery/LinuxForensics.git" "LinuxForensics" || true
  ok "Linux artefact tooling in place"
}

module_browsers() {
  hdr "browsers - history, cache, SQLite forensics"
  apt_install sqlitebrowser sqlite3 python3-sqlparse
  pipx_install "pyhindsight" "dfir-sqlite-parser" || true
  git_sync "https://github.com/obsidianforensics/hindsight.git" "hindsight"
  git_sync "https://github.com/Defense-Cyber-Crime-Center/sqlite-dissect.git" "sqlite-dissect" || true
  ok "browser/SQLite tooling in place"
}

module_email() {
  hdr "email - PST/OST/MSG/mbox"
  apt_install libpff-tools pst-utils mpack ripmime
  pipx_install "extract-msg" "libratom" || true
  ok "email tooling in place"
}

module_malware() {
  hdr "malware - static analysis and triage"
  apt_install \
    yara clamav clamav-freshclam radare2 rizin upx-ucl \
    python3-yara foremost pev die
  pipx_install "flare-capa" "oletools" "pefile" "viv-utils" "msoffcrypto-tool" || true

  # FLOSS (string deobfuscation)
  if [[ ! -x /usr/local/bin/floss ]]; then
    if gh_release_asset "mandiant/flare-floss" "linux.*\.zip$" "/tmp/floss.zip"; then
      (( DRY_RUN )) || {
        unzip -oq /tmp/floss.zip -d /tmp/floss.d
        local f; f="$(find /tmp/floss.d -name floss -type f | head -n1)"
        [[ -n "$f" ]] && install -m0755 "$f" /usr/local/bin/floss && ok "FLOSS installed"
      }
    fi
  fi

  # Didier Stevens suite (pdf-parser, oledump, etc.)
  git_sync "https://github.com/DidierStevens/DidierStevensSuite.git" "DidierStevensSuite"
  (( DRY_RUN )) || {
    local s base
    for s in pdf-parser.py pdfid.py oledump.py zipdump.py base64dump.py translate.py; do
      [[ -f "${OPT_DIR}/DidierStevensSuite/${s}" ]] || continue
      base="${s%.py}"
      printf '#!/usr/bin/env bash\nexec python3 "%s/DidierStevensSuite/%s" "$@"\n' "$OPT_DIR" "$s" \
        > "/usr/local/bin/${base}"
      chmod 0755 "/usr/local/bin/${base}"
    done
  }

  # YARA rule collections
  git_sync "https://github.com/Neo23x0/signature-base.git" "yara-signature-base"
  run freshclam --quiet 2>/dev/null || warn "freshclam update skipped/failed (run later)"
  ok "malware triage tooling in place"
}

module_network() {
  hdr "network - pcap and network forensics"
  apt_install \
    wireshark tshark tcpdump tcpflow tcpreplay ngrep dsniff \
    zeek suricata argus-client p0f whois dnsutils \
    python3-scapy
  pipx_install "pcapkit" || true
  # Let non-root capture (Kali usually asks during install)
  run dpkg-reconfigure -f noninteractive wireshark-common 2>/dev/null || true
  ok "network forensics tooling in place"
}

module_mobile() {
  hdr "mobile - iOS / Android / returns artefact parsers"
  apt_install libimobiledevice-utils ideviceinstaller android-sdk-platform-tools-common adb
  local repo
  for repo in iLEAPP ALEAPP RLEAPP; do
    git_sync "https://github.com/abrignoni/${repo}.git" "$repo"
  done
  venv_from_repo "iLEAPP" "ileapp.py" "ileapp"
  venv_from_repo "ALEAPP" "aleapp.py" "aleapp"
  venv_from_repo "RLEAPP" "rleapp.py" "rleapp"
  ok "mobile artefact tooling in place"
}

module_collection() {
  hdr "collection - Velociraptor offline collectors"
  if [[ ! -x /usr/local/bin/velociraptor ]]; then
    if gh_release_asset "Velocidex/velociraptor" "linux-amd64$" "/tmp/velociraptor"; then
      run install -m0755 /tmp/velociraptor /usr/local/bin/velociraptor && ok "Velociraptor installed"
      log "Build a collector with: velociraptor gui   (or) velociraptor collector <spec.yaml>"
    fi
  else
    ok "Velociraptor already installed"
  fi
}

module_ghidra() {
  hdr "ghidra - reverse engineering suite"
  if have ghidra || pkg_exists ghidra; then
    apt_install ghidra default-jdk
  else
    warn "ghidra not packaged here; fetch from https://github.com/NationalSecurityAgency/ghidra/releases"
  fi
}

module_reporting() {
  hdr "reporting - notes and case output"
  apt_install cherrytree pandoc texlive-xetex graphviz
  pipx_install "mkdocs" "mkdocs-material" || true
  ok "reporting tooling in place"
}

#===============================================================================
# Manifest
#===============================================================================
write_manifest() {
  hdr "Writing manifest"
  (( DRY_RUN )) && { log "skipped (dry run)"; return 0; }
  run mkdir -p "$OPT_DIR"
  {
    echo "# TheMasterBench manifest"
    echo
    echo "- Generated (UTC): $(_ts)"
    echo "- Host: $(hostname)"
    echo "- Distro: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY | cut -d'"' -f2)"
    echo "- Kernel: $(uname -r)"
    echo "- Provisioner: ${SCRIPT_NAME} v${SCRIPT_VERSION}"
    echo
    echo "## Installed entrypoints"
    echo
    echo '| Tool | Path | Version |'
    echo '|------|------|---------|'
    local t p v
    for t in dc3dd dcfldd ddrescue guymager ewfacquire ewfverify ewfmount xmount \
             mmls fls icat istat tsk_recover blkls sorter mactime \
             foremost scalpel bulk_extractor photorec testdisk binwalk \
             log2timeline.py psort.py target-query target-fs acquire \
             vol volatility3 memprocfs avml \
             regripper rip.pl regipy evtx_dump chainsaw hayabusa analyzeMFT \
             INDXRipper mftecmd pecmd evtxecmd amcacheparser \
             apfs-fuse mac-apt unifiedlog_parser plistutil \
             hindsight ileapp aleapp rleapp \
             yara capa floss oledump pdf-parser clamscan \
             tshark zeek suricata velociraptor exiftool hashdeep ssdeep; do
      if p="$(command -v "$t" 2>/dev/null)"; then
        v="$("$t" --version 2>/dev/null | head -n1 | tr -d '|' | cut -c1-60 || true)"
        printf '| %s | %s | %s |\n' "$t" "$p" "${v:-n/a}"
      fi
    done
    echo
    if ((${#MISSING_PKGS[@]})); then
      echo "## Packages unavailable on this release"
      echo
      printf -- '- %s\n' "${MISSING_PKGS[@]}"
      echo
    fi
    if ((${#FAILED_STEPS[@]})); then
      echo "## Steps that failed"
      echo
      printf -- '- %s\n' "${FAILED_STEPS[@]}"
      echo
    fi
    echo "## Layout"
    echo
    echo '```'
    echo "${OPT_DIR}        third-party tools, repos, symbol packs"
    echo "${CASE_ROOT}             per-case working directories (bench-new-case)"
    echo "${EVIDENCE_ROOT}          read-only mount points (bench-mount-ro)"
    echo "${STATE_DIR}   module completion markers"
    echo "${LOG_FILE}    provisioning log"
    echo '```'
  } > "$MANIFEST"
  (( DRY_RUN )) || chown "${TARGET_USER}:${TARGET_USER}" "$MANIFEST" 2>/dev/null || true
  ok "Manifest: ${MANIFEST}"
}

verify_only() {
  hdr "Verification - what is present on this box"
  local group tools t
  declare -A groups=(
    [Acquisition]="dc3dd dcfldd ddrescue ewfacquire ewfverify ewfmount guymager xmount"
    [Filesystem]="mmls fls icat istat tsk_recover apfs-fuse vshadowmount bdemount fvdemount"
    [Carving]="foremost scalpel bulk_extractor photorec testdisk binwalk"
    [Timeline]="log2timeline.py psort.py mactime target-query target-fs acquire"
    [Memory]="vol volatility3 memprocfs avml"
    [Windows]="regripper evtx_dump chainsaw hayabusa analyzeMFT INDXRipper mftecmd evtxecmd"
    [macOS]="mac-apt unifiedlog_parser plistutil apfs-fuse"
    [Browser]="hindsight sqlitebrowser"
    [Malware]="yara capa floss oledump pdf-parser clamscan"
    [Network]="tshark tcpdump zeek suricata"
    [Mobile]="ileapp aleapp rleapp"
    [Collection]="velociraptor"
  )
  for group in "${!groups[@]}"; do
    printf '\n%s%s%s\n' "$C_BLU" "$group" "$C_RESET"
    read -ra tools <<< "${groups[$group]}"
    for t in "${tools[@]}"; do
      if have "$t"; then
        printf '  %s+%s %s\n' "$C_GRN" "$C_RESET" "$t"
      else
        printf '  %s-%s %s\n' "$C_RED" "$C_RESET" "$t"
      fi
    done
  done
  echo
}

#===============================================================================
# Interactive wizard
#
# Runs when the script is started from a terminal with no module selection, or
# with --interactive. Options given on the command line are taken as answers
# (and as the wizard's starting selection); --yes or a non-terminal never
# prompts. Uses whiptail when available, plain read prompts otherwise.
#===============================================================================
use_tui() { have whiptail && [[ "${TERM:-dumb}" != "dumb" ]]; }

want_wizard() {
  case "$INTERACTIVE" in
    1) return 0 ;;
    0) return 1 ;;
  esac
  ((${#SELECTED[@]} == 0)) && [[ -t 0 && -t 1 ]]
}

# whiptail prints its answer on stderr; swap fds so $(...) captures it.
_wt() { whiptail --backtitle "TheMasterBench v${SCRIPT_VERSION}" "$@" 3>&1 1>&2 2>&3; }

# Sets WT_H / WT_W / WT_LIST from the terminal size, for list dialogs.
_wt_size() {
  local lines cols
  lines=$(tput lines 2>/dev/null || echo 24)
  cols=$(tput cols 2>/dev/null || echo 80)
  WT_H=$(( lines - 2 )); WT_W=$(( cols - 4 ))
  (( WT_W > 120 )) && WT_W=120
  WT_LIST=$(( WT_H - 8 ))
}

module_is_done() { [[ -f "${STATE_DIR}/$1.done" ]]; }

# ask_yn <question> [y|n] -- returns 0 for yes, 1 for no; Esc / EOF cancels.
ask_yn() {
  local q="$1" def="${2:-y}" ans rc=0
  if use_tui; then
    local extra=()
    [[ "$def" == "n" ]] && extra=(--defaultno)
    # Height = text lines after wrapping to the box width, plus borders/buttons.
    local h
    _wt_size
    h=$(printf '%s\n' "$q" | awk -v w=$(( WT_W - 4 )) \
      '{ n += (length($0) > w) ? int((length($0) + w - 1) / w) : 1 } END { print n + 7 }')
    (( h > WT_H )) && h=$WT_H
    _wt "${extra[@]}" --title "TheMasterBench" --yesno "$q" "$h" "$WT_W" || rc=$?
    (( rc == 255 )) && die "Cancelled."
    return "$rc"
  fi
  local hint="[Y/n]"; [[ "$def" == "n" ]] && hint="[y/N]"
  while :; do
    printf '\n%s\n' "$q"
    read -rp "${hint} " ans || die "Cancelled."
    ans="${ans:-$def}"
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
    esac
    echo "Please answer y or n."
  done
}

# Choose a starting profile; fills SELECTED (empty for 'custom').
pick_profile() {
  local names=("${PROFILE_ORDER[@]}" custom) choice p i
  if use_tui; then
    _wt_size
    local items=()
    for p in "${PROFILE_ORDER[@]}"; do items+=("$p" "${PROFILE_DESC[$p]}"); done
    items+=(custom "Pick modules yourself")
    choice=$(_wt --title "Profile" --default-item "${PROFILE:-full}" \
      --menu "Choose a starting profile. You can adjust the modules on the next screen." \
      "$WT_H" "$WT_W" "$WT_LIST" "${items[@]}") || die "Cancelled."
  else
    printf '\n%sProfiles%s\n' "$C_BLU" "$C_RESET"
    for i in "${!names[@]}"; do
      p="${names[$i]}"
      printf '  %d) %-9s %s\n' "$(( i + 1 ))" "$p" "${PROFILE_DESC[$p]:-Pick modules yourself}"
    done
    while :; do
      read -rp "Profile [1]: " choice || die "Cancelled."
      choice="${choice:-1}"
      if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#names[@]} )); then
        choice="${names[$(( choice - 1 ))]}"
        break
      fi
      in_array "$choice" "${names[@]}" && break
      echo "Enter a number from 1 to ${#names[@]}."
    done
  fi
  if [[ "$choice" == "custom" ]]; then
    PROFILE=""; SELECTED=()
  else
    PROFILE="$choice"
    read -ra SELECTED <<< "${PROFILE_MODULES[$choice]}"
  fi
}

# Checklist of modules, starting from SELECTED minus SKIPPED. The result
# replaces both (the checklist is the final word), in ALL_MODULES order.
pick_modules() {
  local -A sel=()
  local m
  for m in "${SELECTED[@]}"; do sel[$m]=1; done
  for m in "${SKIPPED[@]}"; do unset "sel[$m]"; done
  sel[core]=1

  if use_tui; then
    _wt_size
    local items=() desc out
    for m in "${ALL_MODULES[@]}"; do
      desc="${MODULE_DESC[$m]}"
      [[ "$m" == "core" ]] && desc="(always included) ${desc}"
      module_is_done "$m" && desc="(done) ${desc}"
      items+=("$m" "$desc" "$([[ -n "${sel[$m]:-}" ]] && echo ON || echo OFF)")
    done
    while :; do
      out=$(_wt --title "Modules" --separate-output --checklist \
        "Space toggles a module, Enter continues. (done) = already completed." \
        "$WT_H" "$WT_W" "$WT_LIST" "${items[@]}") || die "Cancelled."
      [[ -n "$out" ]] && break
      _wt --title "Modules" --msgbox "Select at least one module." 8 40 || true
    done
    sel=([core]=1)
    while IFS= read -r m; do [[ -n "$m" ]] && sel[$m]=1; done <<< "$out"
  else
    local input tok a b i
    while :; do
      printf '\n%sModules%s  (* = selected, done = already completed)\n' "$C_BLU" "$C_RESET"
      for i in "${!ALL_MODULES[@]}"; do
        m="${ALL_MODULES[$i]}"
        printf '  %2d) [%s] %-12s %-5s %s\n' "$(( i + 1 ))" \
          "$([[ -n "${sel[$m]:-}" ]] && echo '*' || echo ' ')" "$m" \
          "$(module_is_done "$m" && echo "done" || true)" "${MODULE_DESC[$m]}"
      done
      echo "Toggle by number or range (e.g. 3,5-7), 'a' = all, 'n' = none, Enter = continue."
      read -rp "> " input || die "Cancelled."
      case "${input,,}" in
        "") break ;;
        a|all)  for m in "${ALL_MODULES[@]}"; do sel[$m]=1; done; continue ;;
        n|none) sel=([core]=1); continue ;;
      esac
      for tok in ${input//,/ }; do
        if [[ "$tok" =~ ^([0-9]+)(-([0-9]+))?$ ]]; then
          a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[3]:-$a}"
          if (( a < 1 || b > ${#ALL_MODULES[@]} || a > b )); then
            warn "Out of range: ${tok}"; continue
          fi
          for (( i = a; i <= b; i++ )); do
            m="${ALL_MODULES[$(( i - 1 ))]}"
            if [[ -n "${sel[$m]:-}" ]]; then unset "sel[$m]"; else sel[$m]=1; fi
          done
        else
          warn "Not a number or range: ${tok}"
        fi
      done
      if [[ -z "${sel[core]:-}" ]]; then
        warn "'core' is always included"; sel[core]=1
      fi
    done
  fi

  SELECTED=(); SKIPPED=()
  for m in "${ALL_MODULES[@]}"; do [[ -n "${sel[$m]:-}" ]] && SELECTED+=("$m"); done
  # Drop the profile name if the selection no longer matches it.
  [[ -n "$PROFILE" && "${SELECTED[*]}" != "${PROFILE_MODULES[$PROFILE]}" ]] && PROFILE=""
  return 0
}

# If any selected module is already completed, offer to re-run it.
ask_force() {
  [[ -n "${SET_BY_FLAG[force]:-}" ]] && return 0
  local done_mods=() m
  for m in "${SELECTED[@]}"; do module_is_done "$m" && done_mods+=("$m"); done
  ((${#done_mods[@]})) || { FORCE=0; return 0; }
  if ask_yn "Already completed: ${done_mods[*]}

Re-run these modules (--force)? If you answer no, they are skipped." n; then
    FORCE=1
  else
    FORCE=0
  fi
}

# The command line that reproduces the current choices without prompts.
#--- Settings: user, folders, hygiene rules -----------------------------------

# valid_path <path> -- absolute, and only characters that are safe unquoted
# in the generated helpers and in sed replacements.
valid_path() {
  [[ "$1" =~ ^/[A-Za-z0-9._/-]*[A-Za-z0-9._-]$ && "$1" != *..* ]]
}

# set_target_user <name> -- switch the examiner account; fails if unknown.
set_target_user() {
  local home
  home="$(getent passwd "$1" 2>/dev/null | cut -d: -f6)" || true
  [[ -n "$1" && -n "$home" ]] || return 1
  TARGET_USER="$1"; TARGET_HOME="$home"
}

# check_settings -- die on settings given as options that cannot work.
check_settings() {
  local name val
  for name in OPT_DIR CASE_ROOT EVIDENCE_ROOT; do
    val="${!name}"
    valid_path "$val" || die "Invalid folder: ${val} (absolute path; letters, digits, . _ - / only)"
  done
}

onoff() { (( $1 )) && echo on || echo off; }

# ask_input <prompt> <default> -- prints the answer; Cancel keeps the default.
# Runs in $(...), so on EOF it returns 1 and the caller must stop.
ask_input() {
  local q="$1" def="$2" ans
  if use_tui; then
    _wt_size
    ans=$(_wt --title "TheMasterBench" --inputbox "$q" 10 "$WT_W" "$def") || ans="$def"
  else
    read -rp "${q} [${def}]: " ans || return 1
  fi
  printf '%s' "${ans:-$def}"
}

tell() {  # tell <message> -- show a short notice in the current UI
  if use_tui; then _wt --title "TheMasterBench" --msgbox "$1" 9 60 || true
  else warn "$1"; fi
}

# edit_path <variable> <label> -- prompt for a folder until it is valid.
edit_path() {
  local val
  val=$(ask_input "$2 (absolute path):" "${!1}") || die "Cancelled."
  if valid_path "$val"; then
    printf -v "$1" '%s' "$val"
  else
    tell "Not a valid folder: ${val}
Use an absolute path with letters, digits, . _ - and / only."
  fi
}

# Menu of settings; pick one to change, or 'next' to continue. The hygiene
# settings only show when the hygiene module is selected.
edit_settings() {
  local hyg=0 choice val i
  in_array hygiene "${SELECTED[@]}" && hyg=1
  local keys labels
  while :; do
    keys=(user tools); labels=(
      "Examiner account:     ${TARGET_USER} (${TARGET_HOME})"
      "Tools folder:         ${OPT_DIR}")
    if (( hyg )); then
      keys+=(cases evidence udev polkit)
      labels+=(
        "Case folder:          ${CASE_ROOT}"
        "Evidence mounts:      ${EVIDENCE_ROOT}"
        "Read-only USB disks:  $(onoff "$UDEV_RO")  (udev rule)"
        "Mounting needs admin: $(onoff "$POLKIT_RULE")  (polkit rule)")
    fi
    keys+=(next); labels+=("Continue to the summary")

    if use_tui; then
      _wt_size
      local items=()
      for i in "${!keys[@]}"; do items+=("${keys[$i]}" "${labels[$i]}"); done
      choice=$(_wt --title "Settings" --default-item next --notags \
        --menu "Choose a setting to change, or continue." \
        "$WT_H" "$WT_W" "$WT_LIST" "${items[@]}") || die "Cancelled."
    else
      printf '\n%sSettings%s\n' "$C_BLU" "$C_RESET"
      for i in "${!keys[@]}"; do
        [[ "${keys[$i]}" == "next" ]] && continue
        printf '  %d) %s\n' "$(( i + 1 ))" "${labels[$i]}"
      done
      read -rp "Number to change, Enter to continue: " val || die "Cancelled."
      if [[ -z "$val" ]]; then
        choice=next
      elif [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 1 && val <= ${#keys[@]} )); then
        choice="${keys[$(( val - 1 ))]}"
      else
        warn "Enter a number from 1 to $(( ${#keys[@]} - 1 ))."; continue
      fi
    fi

    case "$choice" in
      user)
        val=$(ask_input "Account that will use the workstation (groups, pipx tools, file ownership):" "$TARGET_USER") \
          || die "Cancelled."
        set_target_user "$val" || tell "No such user: ${val}" ;;
      tools)    edit_path OPT_DIR "Folder for downloaded tools and repositories" ;;
      cases)    edit_path CASE_ROOT "Folder for case working directories" ;;
      evidence) edit_path EVIDENCE_ROOT "Folder for read-only evidence mounts" ;;
      udev)     UDEV_RO=$(( ! UDEV_RO )) ;;
      polkit)   POLKIT_RULE=$(( ! POLKIT_RULE )) ;;
      next)     return 0 ;;
    esac
  done
}

#--- Saved settings file ------------------------------------------------------
# Settings are saved after each real run and loaded at the start of the next,
# from the home folder of the account that ran sudo. Root reads a file that
# user can edit, so it is parsed as key=value (never sourced) and every value
# is validated.

# bool_val <text> -- prints 1 or 0; fails on anything else.
bool_val() {
  case "${1,,}" in
    1|yes|on|true)  echo 1 ;;
    0|no|off|false) echo 0 ;;
    *) return 1 ;;
  esac
}

# Handles --config / --no-config before anything else, so the file can be
# loaded underneath the other options. --help/--list/--verify skip it.
prescan_config() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)    need_arg "$1" "${2:-}"; CONFIG_FILE="$(realpath -m -- "$2")"; shift ;;
      --no-config) CONFIG_FILE="" ;;
      -h|--help|--list|--verify) CONFIG_FILE=""; return 0 ;;
    esac
    shift
  done
}

load_settings() {
  [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]] || return 0
  local line key val n=0 where
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$(( n + 1 )); where="${CONFIG_FILE}:${n}"
    [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
    [[ "$line" =~ ^[[:space:]]*([a-z_]+)[[:space:]]*=[[:space:]]*(.*[^[:space:]])?[[:space:]]*$ ]] \
      || die "${where}: expected key=value"
    key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]:-}"
    case "$key" in
      user) set_target_user "$val" || die "${where}: no such user: ${val}" ;;
      opt_dir|case_root|evidence_root)
        val="${val%/}"
        valid_path "$val" || die "${where}: invalid folder: ${val}"
        case "$key" in
          opt_dir)   OPT_DIR="$val" ;;
          case_root) CASE_ROOT="$val" ;;
          *)         EVIDENCE_ROOT="$val" ;;
        esac ;;
      udev_ro)     UDEV_RO=$(bool_val "$val")     || die "${where}: udev_ro must be 1 or 0" ;;
      polkit_rule) POLKIT_RULE=$(bool_val "$val") || die "${where}: polkit_rule must be 1 or 0" ;;
      *) warn "${where}: unknown setting '${key}' (ignored)" ;;
    esac
  done < "$CONFIG_FILE"
  CONFIG_LOADED=1
}

# Called in an '||' context (set -e is off inside), so every step is checked.
_write_settings() {
  local dir="${CONFIG_FILE%/*}" owner="" d tmp
  if [[ "$CONFIG_FILE" == "$DEFAULT_CONFIG_FILE" ]]; then
    owner="$DEFAULT_TARGET_USER"
    [[ -d "$DEFAULT_TARGET_HOME" ]] || return 1
    for d in "${dir%/*}" "$dir"; do     # ~/.config, ~/.config/themasterbench
      [[ -d "$d" ]] && continue
      mkdir "$d" && chown "${owner}:" "$d" || return 1
    done
  else
    mkdir -p "$dir" || return 1
  fi
  tmp=$(mktemp "${dir}/.settings.XXXXXX") || return 1
  {
    echo "# TheMasterBench settings, saved $(_ts) by ${SCRIPT_NAME} v${SCRIPT_VERSION}."
    echo "# Loaded on every run; command-line options and the wizard override them."
    echo "# Delete this file to go back to the built-in defaults."
    echo "user=${TARGET_USER}"
    echo "opt_dir=${OPT_DIR}"
    echo "case_root=${CASE_ROOT}"
    echo "evidence_root=${EVIDENCE_ROOT}"
    echo "udev_ro=${UDEV_RO}"
    echo "polkit_rule=${POLKIT_RULE}"
  } > "$tmp" || { rm -f "$tmp"; return 1; }
  chmod 0644 "$tmp" || return 1
  if [[ -n "$owner" ]]; then chown "${owner}:" "$tmp" || return 1; fi
  # rename() replaces a symlink at the destination instead of following it.
  mv -f "$tmp" "$CONFIG_FILE" || { rm -f "$tmp"; return 1; }
}

save_settings() {
  [[ -n "$CONFIG_FILE" ]] && (( ! DRY_RUN )) || return 0
  if _write_settings; then
    ok "Settings saved: ${CONFIG_FILE}"
  else
    warn "Could not save settings to ${CONFIG_FILE}"
  fi
}

settings_status() {
  if [[ -z "$CONFIG_FILE" ]]; then
    echo "not read or saved (--no-config)"
  elif (( DRY_RUN )); then
    printf '%s (%s; not saved in a dry run)' "$CONFIG_FILE" "$( (( CONFIG_LOADED )) && echo loaded || echo none yet)"
  else
    printf '%s (%s; saved when the run starts)' "$CONFIG_FILE" "$( (( CONFIG_LOADED )) && echo loaded || echo new)"
  fi
}

equivalent_cmd() {
  local cmd="sudo ./${SCRIPT_NAME}"
  if [[ -n "$PROFILE" ]]; then
    cmd+=" --profile ${PROFILE}"
  elif [[ "${SELECTED[*]}" == "${ALL_MODULES[*]}" ]]; then
    cmd+=" --all"
  else
    cmd+=" --only $(IFS=,; echo "${SELECTED[*]}")"
  fi
  ((${#SKIPPED[@]})) && cmd+=" --skip $(IFS=,; echo "${SKIPPED[*]}")"
  [[ "$TARGET_USER"   != "$DEFAULT_TARGET_USER"   ]] && cmd+=" --user ${TARGET_USER}"
  [[ "$OPT_DIR"       != "$DEFAULT_OPT_DIR"       ]] && cmd+=" --opt-dir ${OPT_DIR}"
  [[ "$CASE_ROOT"     != "$DEFAULT_CASE_ROOT"     ]] && cmd+=" --case-root ${CASE_ROOT}"
  [[ "$EVIDENCE_ROOT" != "$DEFAULT_EVIDENCE_ROOT" ]] && cmd+=" --evidence-root ${EVIDENCE_ROOT}"
  if [[ -z "$CONFIG_FILE" ]]; then
    cmd+=" --no-config"
  elif [[ "$CONFIG_FILE" != "$DEFAULT_CONFIG_FILE" ]]; then
    cmd+=" --config $(printf '%q' "$CONFIG_FILE")"
  fi
  (( UDEV_RO ))     || cmd+=" --no-udev-ro"
  (( POLKIT_RULE )) || cmd+=" --no-polkit"
  (( FORCE ))   && cmd+=" --force"
  (( DRY_RUN )) && cmd+=" --dry-run"
  printf '%s --yes' "$cmd"
}

summary_text() {
  local done_mods=() m
  for m in "${SELECTED[@]}"; do module_is_done "$m" && done_mods+=("$m"); done
  printf 'Modules:   %s\n' "${SELECTED[*]}"
  [[ -n "$PROFILE" ]] && printf 'Profile:   %s\n' "$PROFILE"
  if ((${#done_mods[@]})); then
    printf 'Completed: %s (%s)\n' "${done_mods[*]}" "$( (( FORCE )) && echo 're-run' || echo 'skipped')"
  fi
  printf 'User:      %s (%s)\n' "$TARGET_USER" "$TARGET_HOME"
  printf 'Tools:     %s\n' "$OPT_DIR"
  if in_array hygiene "${SELECTED[@]}"; then
    printf 'Cases:     %s    Evidence: %s\n' "$CASE_ROOT" "$EVIDENCE_ROOT"
    printf 'Rules:     read-only USB disks %s, mounting needs admin %s\n' \
      "$(onoff "$UDEV_RO")" "$(onoff "$POLKIT_RULE")"
  fi
  printf 'Dry run:   %s\n' "$( (( DRY_RUN )) && echo yes || echo no)"
  printf 'Settings:  %s\n' "$(settings_status)"
  printf '\nEquivalent command:\n  %s\n' "$(equivalent_cmd)"
}

run_wizard() {
  [[ -t 0 && -t 1 ]] || die "--interactive needs a terminal."
  [[ -n "${SET_BY_FLAG[selection]:-}" ]] || pick_profile
  while :; do
    pick_modules
    ask_force
    edit_settings
    ask_yn "$(summary_text)

Proceed? Choose No to change the selection." y && break
  done
  printf '\n%sEquivalent command:%s %s\n' "$C_DIM" "$C_RESET" "$(equivalent_cmd)"
}

#===============================================================================
# CLI
#===============================================================================
usage() {
  cat <<EOF
TheMasterBench v${SCRIPT_VERSION} (${SCRIPT_NAME}) - Kali -> DFIR workstation provisioner

USAGE
  sudo ./${SCRIPT_NAME}                      # interactive setup wizard
  sudo ./${SCRIPT_NAME} --all
  sudo ./${SCRIPT_NAME} --only core,windows,memory
  sudo ./${SCRIPT_NAME} --profile windows
  sudo ./${SCRIPT_NAME} --all --skip ghidra,mobile
  sudo ./${SCRIPT_NAME} --all --force        # re-run completed modules
  sudo ./${SCRIPT_NAME} -i --profile memory  # wizard, starting from a profile
       ./${SCRIPT_NAME} --verify             # report what is installed
       ./${SCRIPT_NAME} --list               # list modules and profiles

OPTIONS
  --all                Run every module
  --only  a,b,c        Run only these modules
  --profile NAME       Run a predefined module set (see --list)
  --skip  a,b,c        Exclude these modules
  --user NAME          Account to set up (default: the user who ran sudo)
  --opt-dir DIR        Folder for downloaded tools (default: ${DEFAULT_OPT_DIR})
  --case-root DIR      Folder for case directories (default: ${DEFAULT_CASE_ROOT})
  --evidence-root DIR  Folder for evidence mounts (default: ${DEFAULT_EVIDENCE_ROOT})
  --no-udev-ro         hygiene: don't force removable disks read-only
                       (removes the rule if an earlier run installed it)
  --no-polkit          hygiene: don't require admin auth to mount removable media
                       (removes the rule if an earlier run installed it)
  --udev-ro, --polkit  Turn a rule back on after a saved "off" setting
  --config FILE        Settings file to load and save
                       (default: ~/.config/themasterbench/settings.conf
                       in the home of the account that ran sudo)
  --no-config          Don't load or save a settings file
  --force              Ignore completion markers and redo everything
  --dry-run            Print what would happen, change nothing
  -i, --interactive    Open the wizard; other options become its defaults
  -y, --yes            Never prompt (also: --non-interactive)
  --list               Show available modules and profiles
  --verify             Check which tools are present (no root required)
  -h, --help           This message

NOTES
  * With no options in a terminal, the wizard asks what to install. Without
    a terminal (CI, pipes) and no options, this help is shown instead.
  * 'core' is always run first when other modules are selected.
  * Settings (--user, folders, rules) are saved after each run and reused by
    the next one. Options on the command line override the saved values.
  * Folder and hygiene settings take effect when hygiene runs; to change them
    after it has completed, re-run it: --only hygiene --force <options>.
  * Missing upstream packages are logged, never fatal.
  * Re-running after a VM rebuild reproduces the same state.
EOF
}

list_modules() {
  printf '\n%sAvailable modules%s\n\n' "$C_BLU" "$C_RESET"
  local m p
  for m in "${ALL_MODULES[@]}"; do
    printf '  %-14s %s\n' "$m" "${MODULE_DESC[$m]:-}"
  done
  printf '\n%sProfiles%s (--profile NAME)\n\n' "$C_BLU" "$C_RESET"
  for p in "${PROFILE_ORDER[@]}"; do
    printf '  %-14s %s\n' "$p" "${PROFILE_DESC[$p]}"
    [[ "$p" == "full" ]] || printf '  %-14s %s%s%s\n' "" "$C_DIM" "${PROFILE_MODULES[$p]}" "$C_RESET"
  done
  echo
}

# need_arg <option> <value> -- die unless the option was given a value.
need_arg() { [[ -n "${2:-}" && "$2" != -* ]] || die "$1 needs a value (try --help)"; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --all)     SELECTED=("${ALL_MODULES[@]}"); PROFILE=""; SET_BY_FLAG[selection]=1 ;;
      --only)    need_arg "$1" "${2:-}"; IFS=',' read -ra SELECTED <<< "$2"
                 PROFILE=""; SET_BY_FLAG[selection]=1; shift ;;
      --profile) need_arg "$1" "${2:-}"
                 [[ -n "${PROFILE_MODULES[$2]:-}" ]] || die "Unknown profile: $2 (see --list)"
                 PROFILE="$2"; read -ra SELECTED <<< "${PROFILE_MODULES[$2]}"
                 SET_BY_FLAG[selection]=1; shift ;;
      --skip)    need_arg "$1" "${2:-}"; IFS=',' read -ra SKIPPED <<< "$2"; shift ;;
      --user)    need_arg "$1" "${2:-}"
                 set_target_user "$2" || die "No such user: $2"; shift ;;
      --opt-dir)       need_arg "$1" "${2:-}"; OPT_DIR="${2%/}"; shift ;;
      --case-root)     need_arg "$1" "${2:-}"; CASE_ROOT="${2%/}"; shift ;;
      --evidence-root) need_arg "$1" "${2:-}"; EVIDENCE_ROOT="${2%/}"; shift ;;
      --no-udev-ro)    UDEV_RO=0 ;;
      --no-polkit)     POLKIT_RULE=0 ;;
      --udev-ro)       UDEV_RO=1 ;;
      --polkit)        POLKIT_RULE=1 ;;
      --config)        shift ;;   # handled by prescan_config
      --no-config)     ;;
      --force)   FORCE=1; SET_BY_FLAG[force]=1 ;;
      --dry-run) DRY_RUN=1; SET_BY_FLAG[dry_run]=1 ;;
      -i|--interactive)          INTERACTIVE=1 ;;
      -y|--yes|--non-interactive) INTERACTIVE=0 ;;
      --list)    list_modules; exit 0 ;;
      --verify)  verify_only; exit 0 ;;
      -h|--help) usage; exit 0 ;;
      *)         die "Unknown option: $1 (try --help)" ;;
    esac
    shift
  done
}

in_array() { local n="$1"; shift; local e; for e in "$@"; do [[ "$e" == "$n" ]] && return 0; done; return 1; }

main() {
  # Saved settings sit underneath the command-line options.
  prescan_config "$@"
  load_settings
  parse_args "$@"

  # Validate names before the wizard uses them as defaults.
  local m
  for m in "${SELECTED[@]}" "${SKIPPED[@]}"; do
    in_array "$m" "${ALL_MODULES[@]}" || die "Unknown module: ${m} (see --list)"
  done
  check_settings

  if want_wizard; then
    is_root || (( DRY_RUN )) || \
      die "The setup wizard installs system packages: run it with sudo (or add --dry-run to preview)."
    run_wizard
  elif (( $# == 0 )); then
    usage; exit 0
  fi

  ((${#SELECTED[@]})) || die "Nothing selected. Use --all, --only <modules> or --profile <name>."
  MANIFEST="${OPT_DIR}/MANIFEST.md"
  is_root || (( DRY_RUN )) || die "Run with sudo (installs system packages)."

  (( DRY_RUN )) || { mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; }
  _log_raw "=== ${SCRIPT_NAME} v${SCRIPT_VERSION} start (user=${TARGET_USER}) ==="
  _log_raw "Equivalent command: $(equivalent_cmd)"
  save_settings

  # Always front-load 'core'
  if ! in_array core "${SELECTED[@]}"; then
    SELECTED=(core "${SELECTED[@]}")
  fi

  hdr "${SCRIPT_NAME} v${SCRIPT_VERSION}"
  log "User:        ${TARGET_USER} (${TARGET_HOME})"
  log "Tools:       ${OPT_DIR}"
  log "Settings:    $(settings_status)"
  log "Modules:     ${SELECTED[*]}"
  ((${#SKIPPED[@]})) && log "Skipping:    ${SKIPPED[*]}"
  (( DRY_RUN ))      && warn "DRY RUN - no changes will be made"

  local start_ts; start_ts=$(date +%s)

  for m in "${SELECTED[@]}"; do
    if ((${#SKIPPED[@]})) && in_array "$m" "${SKIPPED[@]}"; then
      log "Skipping module: ${m}"
      continue
    fi
    if already_done "$m"; then
      ok "Module '${m}' already completed (use --force to redo)"
      continue
    fi
    if ! "module_${m}"; then
      record_failure "module ${m}"
      continue
    fi
    mark_done "$m"
  done

  write_manifest

  local dur=$(( $(date +%s) - start_ts ))
  hdr "Done in $((dur/60))m $((dur%60))s"
  ((${#MISSING_PKGS[@]})) && { warn "${#MISSING_PKGS[@]} package(s) unavailable - see manifest"; }
  ((${#FAILED_STEPS[@]})) && { warn "${#FAILED_STEPS[@]} step(s) failed - see manifest"; }
  cat <<EOF

Next steps:
  1. Log out and back in   (group membership + pipx PATH)
  2. Review               ${MANIFEST}
  3. Start a case         bench-new-case CASE-2026-001 "short description"
  4. Mount evidence       bench-mount-ro /path/to/image.dd
  5. Snapshot this VM     - this is your clean baseline

EOF
}

main "$@"

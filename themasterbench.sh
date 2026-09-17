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
OPT_DIR="/opt/themasterbench"           # third-party tools cloned/unpacked here
STATE_DIR="/var/lib/themasterbench"     # per-module completion markers
LOG_FILE="/var/log/themasterbench.log"  # provisioning log
CASE_ROOT="/cases"                      # working case data
EVIDENCE_ROOT="/evidence"               # mount point for read-only source media
MANIFEST="${OPT_DIR}/MANIFEST.md"

#--- Runtime flags ------------------------------------------------------------
DRY_RUN=0
FORCE=0
ASSUME_YES=1
declare -a SELECTED=()
declare -a SKIPPED=()
declare -a MISSING_PKGS=()
declare -a FAILED_STEPS=()

#--- Target user (the human, not root) ----------------------------------------
TARGET_USER="${SUDO_USER:-${USER:-root}}"
[[ "$TARGET_USER" == "root" && -n "${SUDO_USER:-}" ]] && TARGET_USER="$SUDO_USER"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
TARGET_HOME="${TARGET_HOME:-/root}"

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
  if [[ -d /etc/udisks2 ]] || pkg_installed udisks2; then
    (( DRY_RUN )) || {
      mkdir -p /etc/polkit-1/rules.d
      cat > /etc/polkit-1/rules.d/10-themasterbench-no-automount.rules <<'EOF'
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
  (( DRY_RUN )) || cat > /etc/udev/rules.d/99-themasterbench-removable-ro.rules <<'EOF'
# TheMasterBench - force newly attached removable block devices read-only.
# This is a software safety net, NOT a substitute for a hardware write blocker.
# Comment this file out (or `blockdev --setrw`) when you deliberately need write access.
ACTION=="add", KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{removable}=="1", \
  RUN+="/sbin/blockdev --setro /dev/%k"
ACTION=="add", KERNEL=="sd[a-z][0-9]", SUBSYSTEM=="block", \
  RUN+="/bin/sh -c '[ \"$(cat /sys/block/$(echo %k | sed \"s/[0-9]*$//\")/removable 2>/dev/null)\" = 1 ] && /sbin/blockdev --setro /dev/%k || true'"
EOF
  run udevadm control --reload-rules 2>/dev/null || true
  ok "udev read-only rule installed (99-themasterbench-removable-ro.rules)"

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
MNT="${2:-/evidence/$(basename "$SRC" | tr -c 'A-Za-z0-9._-' '_')}"
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
ROOT="/cases/${CASE_ID}"
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
# CLI
#===============================================================================
usage() {
  cat <<EOF
TheMasterBench v${SCRIPT_VERSION} (${SCRIPT_NAME}) - Kali -> DFIR workstation provisioner

USAGE
  sudo ./${SCRIPT_NAME} --all
  sudo ./${SCRIPT_NAME} --only core,windows,memory
  sudo ./${SCRIPT_NAME} --all --skip ghidra,mobile
  sudo ./${SCRIPT_NAME} --all --force        # re-run completed modules
       ./${SCRIPT_NAME} --verify             # report what is installed
       ./${SCRIPT_NAME} --list               # list modules

OPTIONS
  --all                Run every module
  --only  a,b,c        Run only these modules
  --skip  a,b,c        Exclude these modules
  --force              Ignore completion markers and redo everything
  --dry-run            Print what would happen, change nothing
  --list               Show available modules
  --verify             Check which tools are present (no root required)
  -h, --help           This message

NOTES
  * 'core' is always run first when other modules are selected.
  * Missing upstream packages are logged, never fatal.
  * Re-running after a VM rebuild reproduces the same state.
EOF
}

list_modules() {
  printf '\n%sAvailable modules%s\n\n' "$C_BLU" "$C_RESET"
  local m
  for m in "${ALL_MODULES[@]}"; do
    printf '  %-14s %s\n' "$m" "${MODULE_DESC[$m]:-}"
  done
  echo
}

parse_args() {
  [[ $# -eq 0 ]] && { usage; exit 0; }
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --all)     SELECTED=("${ALL_MODULES[@]}") ;;
      --only)    IFS=',' read -ra SELECTED <<< "${2:?--only needs a list}"; shift ;;
      --skip)    IFS=',' read -ra SKIPPED  <<< "${2:?--skip needs a list}"; shift ;;
      --force)   FORCE=1 ;;
      --dry-run) DRY_RUN=1 ;;
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
  parse_args "$@"

  ((${#SELECTED[@]})) || die "Nothing selected. Use --all or --only <modules>."
  is_root || (( DRY_RUN )) || die "Run with sudo (installs system packages)."

  (( DRY_RUN )) || { mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; }
  _log_raw "=== ${SCRIPT_NAME} v${SCRIPT_VERSION} start (user=${TARGET_USER}) ==="

  # Validate names and always front-load 'core'
  local m
  for m in "${SELECTED[@]}"; do
    in_array "$m" "${ALL_MODULES[@]}" || die "Unknown module: ${m} (see --list)"
  done
  if ! in_array core "${SELECTED[@]}"; then
    SELECTED=(core "${SELECTED[@]}")
  fi

  hdr "${SCRIPT_NAME} v${SCRIPT_VERSION}"
  log "User:        ${TARGET_USER} (${TARGET_HOME})"
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

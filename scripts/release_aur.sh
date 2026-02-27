#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/home/doceasye/Projects/EncryptedJournal"
PKG_DIR="$REPO_DIR/packaging/arch"
AUR_REPO_NAME="encrypted-journal-git"
AUR_TMP_DIR="/tmp/${AUR_REPO_NAME}-aur"
TEST_JOURNAL="/tmp/ej-aur-test-home/journal.json.gz"
SKIP_INSTALL=0
SKIP_PUSH=0
CURRENT_STEP="startup"

usage() {
  cat <<'EOF'
Usage: scripts/release_aur.sh [--no-install] [--no-push]

Options:
  --no-install  Build and validate package, but skip local pacman install + smoke test.
  --no-push     Build/validate package and refresh .SRCINFO, but skip AUR push.
  -h, --help    Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-install)
      SKIP_INSTALL=1
      shift
      ;;
    --no-push)
      SKIP_PUSH=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

on_error() {
  local exit_code=$?
  echo "ERROR: Step failed: ${CURRENT_STEP}" >&2
  exit "$exit_code"
}
trap on_error ERR

set_step() {
  CURRENT_STEP="$1"
  echo "==> $CURRENT_STEP"
}

set_step "1) Show repo status"
cd "$REPO_DIR"
git status -sb

set_step "2) Build Arch package"
cd "$PKG_DIR"
makepkg -f --syncdeps --cleanbuild

set_step "3) Select latest built package"
pkg=$(command ls -1t *.pkg.tar.* | head -n1)
if [[ -z "${pkg:-}" || ! -f "$pkg" ]]; then
  echo "No package artifact found in $PKG_DIR." >&2
  exit 1
fi
echo "Package: $pkg"

set_step "4) Inspect package metadata"
pacman -Qp --info "$pkg"

set_step "5) Inspect package file list"
pacman -Qp --list "$pkg"

if [[ "$SKIP_INSTALL" -eq 0 ]]; then
  set_step "6) Install package"
  sudo pacman -U "$pkg"

  set_step "7) Run isolated smoke test"
  mkdir -p "$(dirname "$TEST_JOURNAL")"
  ENCRYPTED_JOURNAL_FILE="$TEST_JOURNAL" python "$REPO_DIR/scripts/smoke_test.py"
else
  set_step "6-7) Skipping install + smoke test (--no-install)"
fi

set_step "8) Check isolated journal output file"
if [[ -f "$TEST_JOURNAL" ]]; then
  ls -l "$TEST_JOURNAL"
else
  echo "No journal file yet (expected if you did not save an entry)."
fi

set_step "9) Refresh .SRCINFO from PKGBUILD"
makepkg --printsrcinfo > "$PKG_DIR/.SRCINFO"

if [[ "$SKIP_PUSH" -eq 0 ]]; then
  set_step "10) Push packaging files to AUR"
  rm -rf "$AUR_TMP_DIR"
  git clone "ssh://aur@aur.archlinux.org/${AUR_REPO_NAME}.git" "$AUR_TMP_DIR"
  cp PKGBUILD .SRCINFO encrypted-journal.desktop encrypted-journal-launcher "$AUR_TMP_DIR"/
  cd "$AUR_TMP_DIR"
  git add PKGBUILD .SRCINFO encrypted-journal.desktop encrypted-journal-launcher
  if git diff --cached --quiet; then
    echo "No packaging changes to push to AUR."
  else
    git commit -m "Update package from latest omarchy-version"
    git push
  fi
else
  set_step "10) Skipping AUR push (--no-push)"
fi

set_step "Done"
echo "AUR package: ${AUR_REPO_NAME}"

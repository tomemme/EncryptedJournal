#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/home/doceasye/Projects/EncryptedJournal"
PKG_DIR="$REPO_DIR/packaging/arch"
AUR_REPO_NAME="encrypted-journal-git"
AUR_TMP_DIR="/tmp/${AUR_REPO_NAME}-aur"
TEST_JOURNAL="/tmp/ej-aur-test-home/journal.json.gz"

echo "==> 1) Show repo status"
cd "$REPO_DIR"
git status -sb

echo "==> 2) Build Arch package"
cd "$PKG_DIR"
makepkg -f --syncdeps --cleanbuild

echo "==> 3) Select latest built package"
pkg=$(command ls -1t *.pkg.tar.* | head -n1)
echo "Package: $pkg"

echo "==> 4) Inspect package metadata"
pacman -Qp --info "$pkg"

echo "==> 5) Inspect package file list"
pacman -Qp --list "$pkg"

echo "==> 6) Install package"
sudo pacman -U "$pkg"

echo "==> 7) Run isolated journal test (writes only to /tmp)"
mkdir -p "$(dirname "$TEST_JOURNAL")"
ENCRYPTED_JOURNAL_FILE="$TEST_JOURNAL" encrypted-journal || true

echo "==> 8) Check isolated journal output file"
if [[ -f "$TEST_JOURNAL" ]]; then
  ls -l "$TEST_JOURNAL"
else
  echo "No journal file yet (expected if you did not save an entry)."
fi

echo "==> 9) Refresh .SRCINFO from PKGBUILD"
makepkg --printsrcinfo > "$PKG_DIR/.SRCINFO"

echo "==> 10) Push packaging files to AUR"
rm -rf "$AUR_TMP_DIR"
git clone "ssh://aur@aur.archlinux.org/${AUR_REPO_NAME}.git" "$AUR_TMP_DIR"
cp PKGBUILD .SRCINFO encrypted-journal.desktop encrypted-journal-launcher "$AUR_TMP_DIR"/
cd "$AUR_TMP_DIR"
git add PKGBUILD .SRCINFO encrypted-journal.desktop encrypted-journal-launcher
git commit -m "Update package from latest omarchy-version" || echo "Nothing to commit."
git push || true

echo "==> Done"
echo "AUR package: ${AUR_REPO_NAME}"

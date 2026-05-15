# Release Checklist (Omarchy / AUR)

## Scope
- Target branch: `omarchy-version`
- AUR package: `encrypted-journal-git`

## 1) Prepare Repo
- Ensure working tree is clean (except intentional files).
- Push the intended app commits to `origin/omarchy-version` before rebuilding the package.
- Confirm `packaging/arch/PKGBUILD` uses:
  - `source=('git+https://github.com/tomemme/EncryptedJournal.git#branch=omarchy-version')`
- Confirm transient local backup/recovery artifacts are ignored and not staged.

## 2) Build + Validate Package
- `cd packaging/arch`
- `makepkg -f --syncdeps --cleanbuild`
- `pkg=$(command ls -1t *.pkg.tar.* | head -n1)`
- Confirm the build picked up the expected branch tip:
  - `grep '^pkgver=' PKGBUILD`
- `pacman -Qp --info "$pkg"`
- `pacman -Qp --list "$pkg"`

## 3) Functional Smoke Test (Safe)
- `sudo pacman -U "$pkg"`
- Launch with isolated data path:
  - `ENCRYPTED_JOURNAL_FILE=/tmp/ej-aur-test-home/journal.json.gz encrypted-journal`
- Save + load one test entry.

## 4) Refresh Metadata
- `cd packaging/arch`
- Re-run after the package build so VCS `pkgver` is current in both files.
- `makepkg --printsrcinfo > .SRCINFO`
- Verify `PKGBUILD` and `.SRCINFO` report the same `pkgver`.

## 5) Commit Project Changes
- Commit intended packaging/docs automation files in this repo.
  - Usually `packaging/arch/PKGBUILD`, `packaging/arch/.SRCINFO`, and any release-related docs/ignore updates.
- Push to `origin/omarchy-version`.

## 6) Publish To AUR
- `git clone ssh://aur@aur.archlinux.org/encrypted-journal-git.git /tmp/encrypted-journal-git-aur`
- Copy:
  - `PKGBUILD`
  - `.SRCINFO`
  - `encrypted-journal.desktop`
  - `encrypted-journal-launcher`
- Verify only the expected packaging files changed in the AUR checkout before commit.
- Commit + push in AUR repo.

## 7) Post-Release Verification
- Confirm AUR page renders expected metadata.
- Confirm install path works:
  - `yay -Syu encrypted-journal-git`
- Confirm app launches and reads expected journal path.

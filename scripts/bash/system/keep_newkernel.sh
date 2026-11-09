#!/bin/bash
set -euo pipefail

CURRENT_KERNEL="$(uname -r)"
NEW_KERNEL="5.14.0-687.39.1.el9_8.x86_64"

echo "=============================================="
echo "Current running kernel:"
echo "$CURRENT_KERNEL"
echo
echo "Target new kernel:"
echo "$NEW_KERNEL"
echo "=============================================="
echo

# ------------------------------------------------
# 1. Verify target kernel exists
# ------------------------------------------------

if [ ! -d "/lib/modules/$NEW_KERNEL" ]; then
    echo "[ERROR] Target kernel modules directory does not exist:"
    echo "/lib/modules/$NEW_KERNEL"
    exit 1
fi

if [ ! -f "/boot/vmlinuz-$NEW_KERNEL" ]; then
    echo "[ERROR] Target kernel image does not exist:"
    echo "/boot/vmlinuz-$NEW_KERNEL"
    exit 1
fi

echo "[OK] Target kernel exists."
echo

# ------------------------------------------------
# 2. Install required kmod/kernel packages
# ------------------------------------------------

echo "[1/5] Checking kernel packages..."

dnf install -y \
    kmod \
    "kernel-core-$NEW_KERNEL" \
    "kernel-modules-core-$NEW_KERNEL" \
    "kernel-modules-$NEW_KERNEL"

echo
echo "[OK] Kernel packages are installed."
echo

# ------------------------------------------------
# 3. Rebuild module dependencies
# ------------------------------------------------

echo "[2/5] Running depmod..."

depmod -a "$NEW_KERNEL"

echo "[OK] depmod completed."
echo

# ------------------------------------------------
# 4. Check weak modules
# ------------------------------------------------

echo "[3/5] Checking weak-modules..."

if command -v weak-modules >/dev/null 2>&1; then
    weak-modules --add-kernel "$NEW_KERNEL" || true
fi

echo "[OK] weak-modules check completed."
echo

# ------------------------------------------------
# 5. Remove old kernel 611
# ------------------------------------------------

echo "[4/5] Removing old kernel packages..."

OLD_KERNEL="5.14.0-611.55.1.el9_7.x86_64"

OLD_PACKAGES=()

for PKG in \
    "kernel-$OLD_KERNEL" \
    "kernel-core-$OLD_KERNEL" \
    "kernel-modules-core-$OLD_KERNEL" \
    "kernel-modules-$OLD_KERNEL" \
    "kernel-modules-extra-$OLD_KERNEL" \
    "kernel-devel-$OLD_KERNEL" \
    "kernel-headers-$OLD_KERNEL"
do
    if rpm -q "$PKG" >/dev/null 2>&1; then
        OLD_PACKAGES+=("$PKG")
    fi
done

if [ "${#OLD_PACKAGES[@]}" -gt 0 ]; then
    printf '%s\n' "${OLD_PACKAGES[@]}"
    dnf remove -y "${OLD_PACKAGES[@]}"
else
    echo "No old kernel packages found."
fi

echo
echo "[OK] Old kernel cleanup completed."
echo

# ------------------------------------------------
# 6. Rebuild initramfs if required
# ------------------------------------------------

echo "[5/5] Checking initramfs..."

if command -v dracut >/dev/null 2>&1; then
    dracut --regenerate-all --force
fi

echo
echo "=============================================="
echo "FINAL KERNEL STATUS"
echo "=============================================="

echo
echo "Running kernel:"
uname -r

echo
echo "Installed kernel packages:"
rpm -qa | grep '^kernel' | sort || true

echo
echo "Installed kernels:"
ls -1 /lib/modules

echo
echo "GRUB kernels:"
grubby --info=ALL | grep '^kernel=' || true

echo
echo "Default kernel:"
grubby --default-kernel || true

echo
echo "=============================================="
echo "DONE"
echo "=============================================="

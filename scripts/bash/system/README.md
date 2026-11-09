# System Scripts

## keep_newkernel.sh

Switches a RHEL 9 / CloudLinux 9 server to a **target kernel** and removes the old kernel packages.

> **Warning:** this script removes packages and regenerates initramfs for all kernels. Run it only from a console you can recover (KVM / IPMI / VNC), and read the [runbook](keep_newkernel-runbook.md) first.

### Steps

| Step | Action |
|------|--------|
| Pre-check | Verify `/lib/modules/<new>` and `/boot/vmlinuz-<new>` exist, otherwise exit |
| 1/5 | `dnf install` the `kmod`, `kernel-core`, `kernel-modules-core` and `kernel-modules` packages for the target kernel |
| 2/5 | `depmod -a <new>` |
| 3/5 | `weak-modules --add-kernel <new>` (if available) |
| 4/5 | Remove the old kernel packages that are installed (`kernel`, `-core`, `-modules-core`, `-modules`, `-modules-extra`, `-devel`, `-headers`) |
| 5/5 | `dracut --regenerate-all --force` |
| Report | Running kernel, installed packages, `/lib/modules`, GRUB entries and default kernel |

### Configuration

Edit these variables inside the script before running:

| Variable | Description |
|----------|-------------|
| `NEW_KERNEL` | Target kernel version (e.g. `5.14.0-687.39.1.el9_8.x86_64`) |
| `OLD_KERNEL` | Kernel version to remove (e.g. `5.14.0-611.55.1.el9_7.x86_64`) |

### Requirements

`root`, `dnf`, `rpm`, `depmod`, `grubby`, `dracut`.

### Usage

```bash
chmod +x keep_newkernel.sh
sudo ./keep_newkernel.sh
```

See [`keep_newkernel-runbook.md`](keep_newkernel-runbook.md) for the full procedure, the expected output and the reboot / default-kernel steps.

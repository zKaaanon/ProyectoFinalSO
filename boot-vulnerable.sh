#!/bin/bash
qemu-system-x86_64 \
  -kernel /workspaces/ProyectoFinalSO/linux-vulnerable/arch/x86/boot/bzImage \
  -drive file=/workspaces/ProyectoFinalSO/rootfs.img,format=raw,if=virtio \
  -append "root=/dev/vda rw console=ttyS0 nokaslr cryptomgr.notests=0 initcall_debug" \
  -m 1G -smp 2 -nographic \
  -virtfs local,path=/workspaces/ProyectoFinalSO/shared,mount_tag=host0,security_model=none

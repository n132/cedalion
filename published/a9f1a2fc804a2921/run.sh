#!/bin/sh

# rootfs.img is the kernelCTF reproducer image:
#   wget https://storage.googleapis.com/kernelctf-build/files/rootfs_repro_v2.img.gz
#   gzip -d rootfs_repro_v2.img.gz && mv rootfs_repro_v2.img rootfs.img

qemu-system-x86_64 -m 3.5G -nographic -no-reboot \
        -monitor none \
        -enable-kvm -cpu host,-avx512f -smp cores=2 \
        -kernel bzImage \
        -nic user,model=virtio-net-pci \
        -drive file=rootfs.img,if=virtio,cache=none,aio=native,format=raw,discard=on,readonly=on \
        -append "console=ttyS0 root=/dev/vda1 rootfstype=ext4 rootflags=discard ro oops=panic nokaslr quiet"

#!/bin/bash

qemu-system-x86_64 \
    -drive if=pflash,file=OVMF.fd,driver=raw \
    -drive file=data.qcow2,driver=qcow2 \
    -drive file=seed.img,index=1,media=cdrom \
    -netdev user,id=internet,hostfwd=tcp::61235-:22 \
    -device virtio-net-pci,mac=50:54:00:00:00:42,netdev=internet,id=internet-dev \
    -debugcon file:debug.log \
    -global isa-debugcon.iobase=0x402 \
    -m 4G \
    -smp 1 \
    -enable-kvm \
    -machine q35,smm=on,accel=kvm \
    -nographic
    # -drive dir=hda,driver=vvfat,rw=on \

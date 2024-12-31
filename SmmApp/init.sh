#!/bin/bash

# dependencies: whois, cloud-image-utils

#cloud-config
touch network-config
touch meta-data
cat >user-data <<EOF
#cloud-config
users:
  - default
  - name: jpy794
    groups: sudo
    lock_passwd: false
    passwd: $(mkpasswd passwd)
    shell: /bin/bash
ssh_pwauth: true
EOF

genisoimage -output seed.img \
    -volid cidata -rational-rock -joliet \
    user-data meta-data network-config

wget https://cloud-images.ubuntu.com/noble/20241210/noble-server-cloudimg-amd64.img
qemu-img create -f qcow2 -F qcow2 -b cloud-imgs/noble-server-cloudimg-amd64.img data.qcow2 32G

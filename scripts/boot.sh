PDIR="<fillme>"

stty intr ^]
sudo qemu-system-x86_64 \
    -boot c \
    -m 512 \
    -kernel $PDIRlinux-5.4/arch/x86/boot/bzImage \
    -drive format=raw,file=$PDIR/tools/buildroot/output/images/rootfs.ext4 \
    -append "root=/dev/sda rw console=ttyS0,115200 acpi=off nokaslr" \
    -serial stdio \
    -display none \
    -netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no \
    -device e1000,netdev=mynet0,mac=52:55:00:d1:55:01 \
    -virtfs local,id=fsdev0,path=./fs,security_model=none,mount_tag=hostfiles \
    --enable-kvm \
    -s
    -S



#!/bin/bash
# scripts/zfs_setup.sh — Ubuntu 24.04

# 1. Instalar dependencias
apt-get install -y \
    zfsutils-linux libzfs4linux libzfs-dev \
    libfuse3-dev fuse3 \
    pkg-config cmake build-essential

# 2. Crear zpool con disco virtual (para PoC)
truncate -s 10G /tmp/zpool_disk.img
zpool create -f tank /tmp/zpool_disk.img

# 3. Crear dataset para los datos protegidos
zfs create tank/data
zfs set mountpoint=/zpool/data tank/data

# 4. Habilitar compresión (reduce overhead CoW) y checksums
zfs set compression=lz4      tank/data
zfs set checksum=sha256      tank/data
zfs set atime=off            tank/data   # no actualizar atime en lectura

# 5. Snapshot inicial (línea base limpia)
zfs snapshot tank/data@baseline_clean

# 6. Compilar guardian-fs
mkdir -p /opt/guardian/build
cd /opt/guardian
cmake -DCMAKE_BUILD_TYPE=Release \
      -DFUSE_VERSION=3 \
      -S . -B build
cmake --build build --parallel

# 7. Crear directorio mountpoint FUSE
mkdir -p /mnt/protected

# 8. Montar el filesystem FUSE sobre el dataset ZFS
# El proceso guardian_fs actúa de proxy entre /mnt/protected → /zpool/data
/opt/guardian/build/guardian_fs \
    -o allow_other,default_permissions \
    -o max_write=131072 \
    -o kernel_cache \
    --zfs-dataset tank/data \
    /mnt/protected &

echo "Guardian montado en /mnt/protected"
echo "Dataset ZFS subyacente: /zpool/data (tank/data)"
echo "Snapshots: zfs list -t snapshot tank/data"

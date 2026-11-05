#!/usr/bin/env bash
set -u
DIRECT=/mnt/guardian_real/bench
VIA=/mnt/protected/bench
timed() {
    local label=$1; shift
    sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    local t0=$(date +%s%N); "$@"; local t1=$(date +%s%N)
    echo "$label,$(( (t1-t0)/1000000 ))"
}
for rep in 1 2 3 4 5; do
    timed "lectura,directo,$rep"  sh -c "cat $DIRECT/ddfile > /dev/null"
    timed "lectura,guardian,$rep" sh -c "cat $VIA/ddfile > /dev/null"
done

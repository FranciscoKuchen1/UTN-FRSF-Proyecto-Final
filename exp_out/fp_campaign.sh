#!/usr/bin/env bash
# fp_campaign.sh (E6) — falsos positivos del detector C sobre workloads benignos
# CORRER COMO ROOT. Modo ENFORCE sobre /mnt/protected. Por cada workload se
# cuenta cuántos eventos de bloqueo/kill generó (FP = workload benigno
# bloqueado o muerto).
set -u
cd /home/vboxuser/UTN-FRSF-Proyecto-Final
PY=.venv/bin/python
BASE=/mnt/protected/fptest
EVT=/var/log/guardian/events.jsonl
LOG=exp_out/fp_results.csv
SRC=/tmp/opencode/bench_src   # base64(urandom): entropía ~6, NO uniforme

echo "workload,blocked_events,killed_events,duracion_s,completo" > "$LOG"
mkdir -p "$BASE"

run_wl() { # $1=nombre  $2...=comando
    local name=$1; shift
    rm -rf "$BASE/w"; mkdir -p "$BASE/w"
    local ev0=$(wc -l < "$EVT" 2>/dev/null || echo 0)
    local t0=$(date +%s)
    "$@" > "exp_out/fp_${name}.log" 2>&1
    local st=$?
    local t1=$(date +%s)
    local ev1=$(wc -l < "$EVT" 2>/dev/null || echo 0)
    local blocked=$(sed -n "$((ev0 + 1)),${ev1}p" "$EVT" 2>/dev/null | grep -c -E '"event":"(write|rename|unlink)_blocked"' || true)
    local killed=$(sed -n "$((ev0 + 1)),${ev1}p" "$EVT" 2>/dev/null | grep -c '"event":"process_killed"' || true)
    echo "$name,$blocked,$killed,$((t1 - t0)),$([ $st -eq 0 ] && echo si || echo NO)" | tee -a "$LOG"
}

# 1) copia de árbol (cp -r)
run_wl cp_r cp -r src "$BASE/w/src"

# 2) backup comprimido chico (tar czf de docs)
run_wl tar_czf bash -c "tar czf $BASE/w/backup.tar.gz -C . README.md CHANGELOG.md LICENSE"

# 3) gzip de archivo grande incompribible (backup de media)
run_wl gzip_big gzip -c "$SRC" > "$BASE/w/big.gz"

# 4) compilación (gcc)
run_wl gcc bash -c "cp /usr/bin/*.c /dev/null 2>/dev/null; echo 'int main(){return 0;}' > $BASE/w/t.c && gcc -O2 -o $BASE/w/t $BASE/w/t.c"

# 5) git (init/add/commit)
run_wl git bash -c "cd $BASE/w && git init -q && cp /home/vboxuser/UTN-FRSF-Proyecto-Final/README.md . && git add . && git -c user.email=l@l -c user.name=l commit -qm w"

# 6) appends a log (bash)
run_wl appends bash -c "for i in \$(seq 1 300); do echo \"linea \$i de log\" >> $BASE/w/app.log; done"

# 7) rsync masivo (FP conocido: renames de temporales .XXXXXX cambian extensión)
run_wl rsync bash -c "rsync -a --delete /home/vboxuser/UTN-FRSF-Proyecto-Final/src/ $BASE/w/src_r/ && rsync -a --delete /home/vboxuser/UTN-FRSF-Proyecto-Final/docs/ $BASE/w/docs_r/"

# 8) lectura completa del árbol (cat)
run_wl lectura bash -c "tar cf - -C $BASE/w . > /dev/null"

echo "LISTO fp_campaign"

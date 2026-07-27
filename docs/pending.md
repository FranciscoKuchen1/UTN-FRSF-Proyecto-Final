# Pendientes — Guardian FS

Lo necesario para llegar a una prueba funcional en VM con ransomware real.

## Infraestructura

- [ ] VM con ZFS (`tank/data`) y `libfuse3-dev` instalado
- [ ] Compilar `guardian_fs` con `cmake -B build && cmake --build build`

## ML

- [ ] Dataset etiquetado: muestras de E/S benignas + ransomware real
- [ ] Script `python/train_model.py` para entrenar y exportar modelos a `/var/lib/guardian/models/`
- [ ] Ejecutar `ml_server.py` como servicio antes de montar el FUSE

## Testing

- [ ] Prueba con ransomware real en VM aislada (sin red, snapshots previos)
- [ ] Validar detección por entropía, canaries, y bloqueo de escritura
- [ ] Validar que ZFS snapshots se disparan ante `VERDICT_BLOCK`
- [ ] Probar `simulate_ransomware.py` como smoke test previo

## Pulido

- [ ] `pid_table`: liberar slots de procesos muertos (hoy se llenan 128 y mueren)
- [ ] `get_env_or()`: memory leak de startup (bajo impacto, daemon long-running)

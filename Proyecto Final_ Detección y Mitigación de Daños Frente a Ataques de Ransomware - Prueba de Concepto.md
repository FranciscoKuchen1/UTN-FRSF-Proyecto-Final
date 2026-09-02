# 

# 

# 

# 

# **Detección y Mitigación de Daños Frente a Ataques de *Ransomware* \- Prueba de Concepto**

Gómez Enrico, Ivo (Email: ivogomezenrico2015@gmail.com, Legajo: 28685);  
Kuchen, Francisco (Email: franciscokuchen1@gmail.com, Legajo: 27930);  
Universidad Tecnológica Nacional, Facultad Regional Santa Fe  
Proyecto Final  
Director: Dr. Pablo Pessolani  
Codirectores: Ing. David Harispe

# 2026, Primer Cuatrimestre

# **Descripción**

En los últimos años, el ransomware se ha consolidado como una de las principales amenazas de seguridad informática, afectando tanto a usuarios individuales como a organizaciones públicas y privadas. Este tipo de malware o software malicioso se caracteriza por la modificación masiva de archivos mediante cifrado que impide al propietario de los mismos acceder a la información. Es un tipo de “secuestro de datos” por el cual los atacantes piden el pago de un rescate para entregar al propietario la clave de encriptación. El pago generalmente se realiza en criptomonedas para conservar el anonimato e impedir la traza del dinero. El ataque es producido en períodos de tiempo muy reducidos por un vector de ataque (existen muchas variantes), lo que dificulta la detección y la recuperación de la información afectada.

Las estrategias tradicionales para enfrentar este malware suelen ser las copias de seguridad periódicas, soluciones antivirus o sistemas de detección de intrusiones, pero individualmente presentan limitaciones frente a este tipo de ataques. En general, suelen ser parciales y tardías, porque no se garantiza la recuperación de la totalidad de los datos. En particular, resultan insuficientes cuando no se dispone de backups recientes, cuando los archivos de backups contienen el propio malware en estado latente o cuando el ataque compromete grandes volúmenes de datos o datos críticos antes de ser detectado.

En este contexto, surgen distintas alternativas para abordar la recuperación de datos. Entre ellas, los sistemas de archivos basados en el paradigma Copy-on-Write (CoW), proponen un enfoque que evita la sobrescritura directa de bloques, permitiendo conservar versiones anteriores de la información mediante snapshots. No obstante, existen también otras estrategias y herramientas que podrían contribuir a la recuperación de datos, por lo que resulta necesario analizar su efectividad en escenarios reales. Aprovechando algunas características de ciertos sistemas de archivos, se pueden disparar alarmas/eventos ante determinadas operaciones que lleven a la detección de un ataque e impedir las escrituras y modificaciones en los archivos/directorios alarmados.

El proyecto propuesto tiene como objetivo evaluar la efectividad de las diferentes técnicas para la detección de ataques y recuperación de datos frente a escenarios de alteración masiva de archivos. Para ello, se desarrollará una prueba de concepto (PoC) y se la someterá a ataques de diferentes tipos de ransomware. En una primera instancia, se analizarán herramientas existentes y sus capacidades de recuperación. En función de los resultados obtenidos, se evaluará la necesidad de diseñar e implementar una solución a medida que permita mejorar/complementar los mecanismos de recuperación observados o que agregue características que faciliten la detección de ataques.

El objetivo final del proyecto propuesto es determinar qué tan efectivas resultan estas estrategias en términos de recuperación de información, identificando sus ventajas, limitaciones y posibles mejoras, a partir de métricas como la pérdida de datos, el tiempo de recuperación y el costo en almacenamiento adicional.

# 

# **Objetivos**

# ***Objetivo General***

Evaluar la efectividad de distintas estrategias y herramientas existentes para la detección y recuperación de datos frente a ataques de ransomware y proponer e implementar otras a modo de Prueba de Concepto (PoC). Se procederá a evaluar la detección de los incidentes y medir la pérdida de información, los tiempos de recuperación y los costos de almacenamiento adicionales requeridos para la protección.

# 

# ***Objetivos Específicos***

* Identificar técnicas existentes para la detección de ataques y la recuperación de datos comprometidos para determinar su efectividad para un conjunto seleccionado de familias de ransomware.  
* Medir y analizar la pérdida de información, tiempo de recuperación y costo de almacenamiento adicional relacionada a la detección y recuperación de datos para determinar el esfuerzo y recursos requeridos.  
* Implementar un entorno de prueba virtualizado con el que se puedan simular ataques de ransomware para evaluar la efectividad y eficiencia de las diferentes herramientas existentes y propuestas.  
* Evaluar el uso de sistemas de archivos Copy-on-Write como ZFS (Zettabyte File System) y su funcionalidad de snapshots como mecanismo principal para la recuperación de datos.   
* Diseñar e implementar, si es necesario, un sistema de monitoreo de archivos como PoC utilizando Filesystem in UserSpace (FUSE) en sistema Linux para interceptar operaciones de escritura y detectar comportamientos anómalos.  
* Desarrollar, si es necesario, un mecanismo de mitigación basado en FUSE (PoC) que permita bloquear o registrar modificaciones sospechosas durante ataques simulados.

# **Alcance**

# ***Alcance del Producto***

* Se incluye:   
  * Entorno controlado de almacenamiento basado en ZFS para pruebas de resiliencia.  
  * Conjunto de scripts/herramientas para simulación de comportamiento tipo ransomware (modificación/cifrado de archivos).  
  * Configuración de snapshots para versionado de datos.  
  * Mecanismo de recuperación de información a partir de snapshots.  
  * Registro de eventos y cambios en el sistema de archivos durante la simulación.  
  * Reportes comparativos de impacto y recuperación en distintos escenarios.  
* Se excluye:  
  * Desarrollo de ransomware.  
  * Integración con soluciones comerciales de backup.  
  * Despliegue en infraestructura productiva.  
  * Automatización avanzada de monitoreo en tiempo real.

***Alcance del Proyecto***

* Relevamiento conceptual sobre ransomware y mecanismos de protección en sistemas de archivos.  
* Diseño del entorno de pruebas (PoC) y definición de escenarios (con y sin snapshots).  
* Implementación del entorno en ZFS.  
* Desarrollo de scripts para simular ataques de cifrado de archivos.  
* Ejecución de pruebas controladas en entornos virtualizados de ataques de ransomware.  
* Evaluación del comportamiento de Copy-on-Write frente a modificaciones maliciosas.  
* Pruebas de recuperación de datos en distintos escenarios.  
* Medición de resultados (pérdida de datos, tiempos de recuperación e integridad).  
* Análisis de resultados y elaboración de conclusiones.


# **Fundamentación y Justificación**

***Fundamentación***

El ransomware es un malware que secuestra sistemas o cifra datos, exigiendo un rescate económico para su liberación. Potenciado por avances técnicos y la comercialización del Ransomware as a Service (RaaS), representa una amenaza crítica que causa pérdidas corporativas multimillonarias anualmente a nivel global (Oz et al., 2022; Brewer, 2019).

Como mecanismo de defensa en el sistema operativo, se plantea la integración de ZFS y FUSE. Por un lado, la tecnología FUSE (Filesystem in UserSpace) permite interceptar sincrónicamente las operaciones de entrada/salida (E/S) sin modificar el kernel, detectando anomalías antes de que el ransomware modifique el disco. De forma complementaria, el robusto sistema de archivos ZFS emplea el paradigma Copy-on-Write (CoW). Al no sobrescribir los bloques físicos directamente y utilizar *checksums* de validación, ZFS permite crear *snapshots* (instantáneas) inmutables de los datos. Esto garantiza la integridad de la información y una restauración exacta y eficiente ante cualquier daño o secuestro de la información (Dakic et al., 2024).

***Justificación***

El ransomware es una amenaza que paraliza organizaciones y causa pérdidas millonarias a nivel global (Brewer, 2016; O'Kane et al., 2017). Su evolución tecnológica y la adopción de modelos como el Ransomware as a Service (RaaS) (Oz et al., 2022\) hacen que los métodos de defensa tradicionales, como los antivirus o los backups periódicos, resulten insuficientes. Esto ocurre porque el malware actúa a gran velocidad y, con frecuencia, logra cifrar las propias copias de seguridad antes de ser detectado.

El Ransomware se enmascara u oculta como un proceso normal ejecutado por un usuario ordinario (con o sin privilegios), lo que hace muy difícil la detección de sus intenciones. Aún así, debe llevar a cabo su tarea de forma sigilosa, pero a la vez realizar operaciones de lectura y cifrado de grandes volúmenes de datos, presenta ciertos comportamientos que lo exponen a su detección.

Si no se adopta una arquitectura de almacenamiento resiliente, las empresas quedan completamente expuestas. Un ataque exitoso implica la interrupción total de las operaciones, la pérdida irreversible de datos críticos y la presión de ceder a una extorsión financiera.

Este proyecto propone investigar acerca de los mecanismos de detección y recuperación utilizando una Prueba de Concepto (PoC). Primero, utilizar el sistema de archivos ZFS, cuya arquitectura Copy-on-Write (CoW) permite generar instantáneas (snapshots) inmutables casi sin consumir espacio adicional (Dakic et al., 2024), garantizando siempre la disponibilidad de una versión limpia de los archivos. Segundo, implementar FUSE (Filesystem in UserSpace) para interceptar y auditar las operaciones del sistema de archivos (lectura y escritura) en tiempo real (Varia et al., 2021).

Están fuera del alcance de este proyecto la detección del medio utilizado para la infección de archivos o alteración de procesos previos a la ejecución del código de ransomware.

El desarrollo de esta PoC se justifica en la necesidad de demostrar empíricamente que la combinación del monitoreo activo de FUSE y la recuperación mediante snapshots de ZFS permite identificar y frenar un ataque antes de que los datos se modifiquen en el disco. El proyecto proveerá métricas reales sobre tiempos de recuperación, almacenamiento requerido y prevención de pérdida de datos, ofreciendo a los administradores de sistemas una estrategia concreta y efectiva para defender sus infraestructuras operativas.

# **Aportes**

Consideramos que los beneficios que se quieren aportar con el desarrollo de este proyecto son valiosos. Si bien la PoC utilizará en principio, *Zettabyte File System* (ZFS) o FUSE (Sistema de Archivos en Espacio de Usuario), junto con sus herramientas asociadas, las experiencias y conclusiones obtenidas del proyecto permitirán que    
otros investigadores y compañías desarrolladoras de soluciones de protección de datos, aplicarlas a otros sistemas de archivos y herramientas de detección tales como Antivirus, Antimalware, Detectores de Intrusos, etc.

***Aporte Técnico y a la Disciplina***

Implementación de un mecanismo de recuperación de datos basado en snapshots y técnicas avanzadas de detección de encriptación de archivos mediante FUSE y el versionado de datos de ZFS.

***Aporte Práctico***

Provisión de un entorno de pruebas controlado y funcional que permite simular ataques, evaluar el comportamiento de familias de ransomware específicas y ejecutar rutinas de recuperación de datos exactas sin comprometer la infraestructura subyacente.

***Aporte Económico***

La incorporación de este tipo de soluciones permiten reducir costos, recursos y tiempo potenciales al momento de prevenir o recuperar los datos ante un ataque de Ransomware, dado la importancia de los datos para el proceso productivo del negocio, cuya encriptación o inconsistencia da lugar a diversos problemas operativos tanto de la pérdida de beneficio cuando no se está operando como de costos mayores si estos datos son vendidos o usados para otros fines como penetrar a otros sistemas. Es importante considerar los perjuicios no tan mensurables producidos por la pérdida de prestigio y reputación de una organización al sufrir un ataque de ransomware y ser paralizada en su operación.

***Aporte Personal***

El desarrollo de este proyecto impulsa y fortalece el dominio técnico en la administración de sistemas de archivos avanzados (ZFS), programación de scripts y manejo de módulos en espacio de usuario (FUSE) para entornos Linux, junto con el análisis de comportamiento de malware criptográfico a nivel de operaciones de entrada y salida (E/S).

# **Metodologías**

**Enfoque y Diseño de Investigación** 

La investigación adopta un enfoque cuantitativo con un diseño experimental. Se manipulará de forma controlada la variable independiente (el mecanismo de contención: sistema sin protección, mitigación estática con ZFS, y defensa activa ZFS+herramienta de detección) para medir su impacto sobre las variables dependientes (porcentaje de pérdida de información, Objetivo de Tiempo de Recuperación \- RTO, y sobrecarga de almacenamiento). El nivel de la investigación es explicativo y aplicativo, estructurado para recolectar evidencia empírica irrefutable sobre la viabilidad transaccional de la arquitectura propuesta frente a rutinas de cifrado de alta velocidad.

**Modelo de Desarrollo de Software** 

Se ejecutará un modelo de Prototipado Evolutivo acoplado a ciclos iterativos de validación. La construcción de la herramienta de detección requiere ajustes heurísticos de alta precisión para evitar la degradación del rendimiento del sistema operativo (kernel panic/deadlocks). El prototipo se refinará progresivamente: desde la intercepción pasiva y el registro de llamadas al sistema (syscalls), hasta la inyección de latencia y el bloqueo síncrono definitivo de las operaciones de escritura anómalas.

**Fases Metodológicas**

* **Fase 1: Modelado de Amenazas y Perfilado de E/S:** Análisis de las primitivas de interacción de familias de ransomware para Linux. Definición de la línea base del comportamiento normal del sistema de archivos y establecimiento de los umbrales de anomalía (tasas de sobreescritura, medición de entropía en buffers de datos, secuencias masivas de open/write/rename).  
* **Fase 2: Emplazamiento de la Infraestructura Confinada:** Configuración de un entorno de virtualización estanco. Aislamiento absoluto de red y supresión de volúmenes compartidos con el hipervisor. Despliegue de los zpools, configuración de los *datasets* en ZFS y establecimiento de la retención determinista mediante *snapshots* inmutables basados en el paradigma Copy-on-Write (CoW).  
* **Fase 3: Instrumentación del Prototipo (PoC):** Programación de la herramienta de detección. Mapeo de las estructuras de datos y desarrollo de los *callbacks* necesarios para retener el hilo de ejecución de las llamadas al sistema, evaluar el contenido mediante modelos de machine learning y emitir un veredicto de bloqueo antes del vaciado (flush) hacia el dispositivo de bloques ZFS.  
* **Fase 4: Ejecución Experimental Controlada:** Inyección de simuladores de carga de trabajo destructiva (fase de calibración) y ejecución de muestras reales de ransomware compilado para arquitecturas Linux (fase de destrucción). Medición del comportamiento del sistema bajo ataques multihilo enfocados en la paralización de E/S.  
* **Fase 5: Extracción, Telemetría y Análisis:** Cuantificación exacta del volumen de bytes comprometidos antes de la activación del bloqueo. Medición temporal del proceso de *rollback* de los *snapshots* de ZFS. Cálculo de la degradación del rendimiento de E/S (throughput y latencia) inducida por el motor de intercepción durante el uso legítimo del sistema.

# **Cronograma**

| Mes | Etapa Metodológica | Tareas Principales | Hito (Milestone) |
| :---: | :---: | ----- | ----- |
| **Mes 1** | Relevamiento y Diseño | Estudio del campo a analizar. Selección de herramientas. Diseño de arquitectura. | Definición de métricas y escenarios. |
| **Mes 2** | Preparación paralela | Investigación: Búsqueda y recolección de muestras de Ransomware (Linux). Infraestructura: Despliegue de VMs y volúmenes ZFS/Btrfs. | Entorno listo y muestras ejecutables almacenadas y aisladas. |
| **Mes 3** | Análisis, elección y desarrollo de la herramienta de detección. | Análisis y elección de las diferentes herramientas de detección que se pueden implementar. Desarrollo inicial de la herramienta elegida. | Elección de la mejor herramienta y primera aproximación al desarrollo. |
| **Mes 4** | Implementación avanzada herramienta de detección. | Mejora de la lógica de detección de anomalías e interrupción de proceso maligno. | Herramienta de detección de ataques. |
| **Mes 5** | Integración de modelo de Machine Learning a la herramienta. | Elaboración de modelo de Machine Learning e incorporación a la herramienta de detección. | Finalización de la herramienta de detección. |
| **Mes 6** | Pruebas | Pruebas exhaustivas contra múltiples familias de malware. | Validación de que la herramienta funciona como corresponde, hito (80%-90%) de casos de éxito de detección. |
| **Mes 7** | Análisis de Resultados | Procesamiento estadístico. Generación de reportes comparativos de impacto. | Resultados tabulados y gráficas finales. |
| **Mes 8** | Cierre | Redacción del documento final del proyecto. Preparación de la defensa y presentación. | Entrega del Proyecto Final. |

# 

# **Informes de Avance**

**Informe de Avance 1**

* **Fecha de entrega:** 30/08/2026.  
* **Contenido propuesto:** Presentación de la arquitectura general del entorno. Evidencia de la configuración inicial del sistema de archivos ZFS y las muestras recolectadas de Ransomware. Análisis de herramientas de detección y elección de la mejor, desarrollo inicial de la herramienta.

**Informe de Avance 2**

* **Fecha de entrega:** 04/10/2026.  
* **Contenido propuesto:** Implementación más avanzada de la herramienta y desarrollo de modelo de Machine Learning. Recolección de datos para el modelo.

**Informe de Avance 3**

* **Fecha de entrega:** 01/11/2026  
* **Contenido propuesto:** Prototipo inicial de los módulos de detección y recuperación de ataques luego del conjunto base de pruebas.

# **Gestión de Riesgo e Impacto Ambiental**

**Análisis de Riesgo**

La siguiente matriz clasifica los riesgos identificados según su probabilidad de ocurrencia y su impacto en el proyecto.

| Probabilidad / Impacto | Bajo | Medio | Alto |
| :---: | :---: | :---: | :---: |
| **Baja** | *Trivial* | *Tolerable* | *Moderado (Riesgo 2,Riesgo 5\)* |
| **Media** | *Tolerable* | *Moderado (Riesgo 4\)* | *Significativo (Riesgo 1\)* |
| **Alta** | *Moderado* | *Significativo (Riesgo 3\)* | *Crítico* |

**Riesgo 1: Degradación del rendimiento del sistema operativo o fallos críticos (Kernel panic/deadlocks)**

* **Descripción:** La intercepción de operaciones de entrada/salida (E/S) mediante FUSE genera bloqueos en el sistema operativo que impiden su funcionamiento normal.  
* **Tipo:** Técnico / Interno  
* **Probabilidad:** Media  
* **Impacto:** Alto  
* **Estrategias para mitigar la probabilidad:**  
  * Ejecutar un modelo de Prototipado Evolutivo, iniciando con intercepción pasiva y registro de llamadas (syscalls) antes de aplicar bloqueos síncronos.  
  * Ajustar heurísticamente los umbrales de anomalía de alta precisión.  
* **Estrategias para mitigar el impacto:**  
  * Desplegar el prototipo exclusivamente en el entorno de virtualización estanco definido en la Fase 2 metodológica.  
* **Plan de contingencia:**  
  * Revertir el mecanismo FUSE a un modo estrictamente asíncrono y de auditoría (solo lectura/registro), delegando la contención del ataque primariamente a los snapshots inmutables de ZFS.

**Riesgo 2: Fuga del ransomware simulado hacia la infraestructura física subyacente**

* **Descripción:** Las muestras de ransomware ejecutadas en la fase de destrucción comprometen el hipervisor o el sistema operativo base del investigador.  
* **Tipo:** Técnico / Externo  
* **Probabilidad:** Baja  
* **Impacto:** Alto  
* **Estrategias para mitigar la probabilidad:**  
  * Configurar un emplazamiento confinado con aislamiento absoluto de red.  
  * Suprimir totalmente los volúmenes compartidos entre las máquinas virtuales y el hipervisor.  
* **Estrategias para mitigar el impacto:**  
  * Garantizar la retención determinista mediante snapshots Copy-on-Write (CoW) en el sistema de archivos del hipervisor físico.  
* **Plan de contingencia:**  
  * Destrucción inmediata de las máquinas virtuales comprometidas y restauración del entorno físico desde copias de seguridad offline o snapshots generados de forma previa a la ejecución de las muestras.

**Riesgo 3: Ineficacia del modelo en la detección de muestras de ransomware no perfiladas**

* **Descripción:** La herramienta de detección y el modelo de Machine Learning no logran identificar secuencias maliciosas debido a variaciones en las tasas de sobrescritura o a una baja entropía en los buffers de datos del atacante.  
* **Tipo:** Técnico / Evaluación de resultados  
* **Probabilidad:** Alta  
* **Impacto:** Medio  
* **Estrategias para mitigar la probabilidad:**  
  * Desarrollar un modelado de amenazas exhaustivo y establecer una línea base precisa del comportamiento normal del sistema de archivos.  
  * Realizar pruebas exhaustivas contra múltiples familias de malware durante el Mes 6 del cronograma.  
* **Estrategias para mitigar el impacto:**  
  * Generar reportes comparativos que expongan de forma transparente el porcentaje de pérdida de información alcanzado antes del bloqueo.  
* **Plan de contingencia:**  
  * Replantear el objetivo de la herramienta FUSE como un sistema de retraso computacional (inyección de latencia) en lugar de un bloqueador definitivo , priorizando la efectividad del rollback de ZFS para la recuperación.

**Riesgo 4: Incumplimiento de los plazos establecidos en el cronograma**

* **Descripción:** Subestimación del tiempo requerido para el desarrollo del entorno o demoras técnicas imprevistas que provocan un retraso en la entrega de los informes de avance y finalización del proyecto.  
* **Tipo:** Organizacional / Interno  
* **Probabilidad:** Media  
* **Impacto:** Medio  
* **Estrategias para mitigar la probabilidad:**  
  * Implementar revisiones semanales del progreso respecto a los hitos definidos en el cronograma.  
  * Incorporar márgenes de tiempo de holgura en las fases de implementación avanzada y pruebas.  
* **Estrategias para mitigar el impacto:**  
  * Priorizar el desarrollo de las funcionalidades críticas de la Prueba de Concepto (PoC) sobre los componentes secundarios.  
* **Plan de contingencia:**  
  * Solicitar una readecuación de plazos a la dirección del proyecto y reducir la cantidad de familias de ransomware evaluadas en la Fase 4\.

**Riesgo 5: Pérdida o indisponibilidad de un integrante del equipo de investigación**

* **Descripción:** Ausencia prolongada o deserción de uno de los desarrolladores, lo que genera una reducción de la capacidad operativa y detiene la ejecución de las fases metodológicas.  
* **Tipo:** Organizacional / Interno  
* **Probabilidad:** Baja  
* **Impacto:** Alto  
* **Estrategias para mitigar la probabilidad:**  
  * Mantener una comunicación constante y distribuir equitativamente la carga de trabajo semanal.  
  * Documentar exhaustivamente cada etapa del diseño, código y configuración del entorno ZFS.  
* **Estrategias para mitigar el impacto:**  
  * Ejecutar las tareas técnicas de forma colaborativa para evitar silos de conocimiento y asegurar que ambos miembros dominen la arquitectura.  
* **Plan de contingencia:**  
  * Reasignar las tareas críticas al integrante restante, notificar formalmente a la dirección y reajustar el alcance funcional del proyecto descartando la integración del modelo de Machine Learning.

**Análisis de Impacto Ambiental**

La investigación e implementación de tecnologías informáticas conlleva consecuencias directas sobre el medio ambiente que deben ser cuantificadas y mitigadas.

**Fuentes de impacto ambiental negativo:**

* **Consumo energético:** El diseño de la arquitectura y la ejecución de entornos virtualizados (VMs, despliegue de zpools) para la simulación de cargas de trabajo destructivas implican un consumo eléctrico sostenido en servidores o estaciones de trabajo.  
* **Huella de carbono por IA:** La evaluación de contenido mediante la integración de un modelo de Machine Learning requerirá ciclos de procesamiento y entrenamiento que conllevan emisiones de CO2.

**Estrategias de mitigación:**

* Implementar un apagado automatizado del entorno de virtualización estanco durante los períodos de inactividad investigativa para reducir el consumo en kWh.  
* Optimizar la lógica de intercepción en FUSE para evitar la sobrecarga de la CPU y la degradación inútil del rendimiento del sistema operativo durante las fases de calibración.  
* Utilizar la métrica ML CO2 Impact para estimar las emisiones generadas por el entrenamiento del modelo de Machine Learning, documentando el consumo asociado y ajustando los tiempos de entrenamiento.

**Impactos ambientales positivos:**

* El objetivo del proyecto radica en la recuperación rápida de datos frente a la alteración masiva. La aplicación exitosa de este sistema en infraestructuras de producción evita el reemplazo o descarte prematuro de equipos de almacenamiento secuestrados o inutilizados por malware de grado destructivo, reduciendo indirectamente la generación de residuos electrónicos (e-waste) a nivel corporativo.

# **Referencias**

O'Kane, P., Sezer, S. and Carlin, D. (2018). Evolution of ransomware. IET Netw., 7: 321-327. [https://doi.org/10.1049/iet-net.2017.0207](https://doi.org/10.1049/iet-net.2017.0207)

Richardson, R., and North, M. (2017). Ransomware: Evolution, Mitigation and Prevention. Kennesaw State University. [https://digitalcommons.kennesaw.edu/cgi/viewcontent.cgi?article=5312\&context=facpubs](https://digitalcommons.kennesaw.edu/cgi/viewcontent.cgi?article=5312&context=facpubs)

Lee, S. et al. (2021). Rcryptect: Real-time detection of cryptographic function in the user-space filesystem. Computers & Security, Volume 112, 102512\. [https://doi.org/10.1016/j.cose.2021.102512](https://doi.org/10.1016/j.cose.2021.102512)

Dakic, V., Kovac, M., & Videc, I. (2024). High-Performance Computing Storage Performance and Design Patterns—Btrfs and ZFS Performance for Different Use Cases. Computers, 13(6), 139\. [https://doi.org/10.3390/computers13060139](https://doi.org/10.3390/computers13060139)

Beaman, C. et al. (2021). Ransomware: Recent advances, analysis, challenges and future research directions. Computers & Security Volume 111, 102490\. [https://doi.org/10.1016/j.cose.2021.102490](https://doi.org/10.1016/j.cose.2021.102490)

Brewer, R. (2016). Ransomware attacks: detection, prevention and cure. Network Security  
Volume 2016, Issue 9, Pages 5-9. [https://doi.org/10.1016/S1353-4858(16)30086-1](https://doi.org/10.1016/S1353-4858\(16\)30086-1)

McConnell, S. (1996). Rapid Development: Taming Wild Software Schedules. Developer Best Practices. Microsoft Press. [https://learning.oreilly.com/library/view/rapid-development-taming/9780735634725/](https://learning.oreilly.com/library/view/rapid-development-taming/9780735634725/)
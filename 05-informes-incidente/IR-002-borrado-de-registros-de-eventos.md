# IR-002 · Borrado de registros de eventos en endpoint Windows

> **Incidente simulado.** Los hechos provienen de una simulación manual con `wevtutil` ejecutada por mí en mi propio laboratorio (no existía la prueba de Atomic Red Team para esta técnica). Este informe sigue el formato de [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (abril de 2025, alineada con CSF 2.0). Usa los nombres de fase clásicos y entre paréntesis la función de la Rev. 3 a la que equivalen.

## 1. Resumen ejecutivo

| | |
|---|---|
| **ID** | IR-002 |
| **Tipo de incidente** | Evasión de defensas: destrucción de evidencia (borrado de registros) |
| **Fechas** | 04-11-2026 y 05-11-2026, hora de Chile (UTC-3) |
| **Activo afectado** | `WIN11-ENDPOINT` (192.168.56.30), usuario `analista`, integridad High |
| **Detectado por** | Wazuh 4.14.9: regla de fábrica 63103 (nivel 5) y **regla propia 100100** (nivel 12) |
| **Severidad** | Alta si fuera real (indica un equipo comprometido que oculta actividad). En el laboratorio, sin impacto |
| **Estado** | Cerrado. Brecha de detección corregida con regla propia |

El usuario `analista` vació el registro de Seguridad de Windows con `wevtutil cl Security`. Wazuh solo generó un aviso genérico de nivel 5 a partir del evento 1102 de Windows. El comando, que Sysmon sí registró, no tenía ninguna regla que lo interpretara. Escribí la regla 100100 (nivel 12, MITRE T1070.001), la validé y repetí el ataque al día siguiente sobre el registro de Aplicación: la alerta apareció.

## 2. Preparación (equivale a Govern, Identify y Protect)

Lo que existía:
- Sysmon (configuración SwiftOnSecurity) y agente Wazuh enviando los eventos al SIEM.
- Regla de fábrica 63103 para el evento 1102 (*The audit log was cleared*).

Lo que faltaba:
- Una regla sobre el **comando** de borrado: la de fábrica solo mira el resultado, y únicamente para el registro de Seguridad.
- Sincronización de hora (NTP) entre el servidor Wazuh y el endpoint.

## 3. Detección y análisis (equivale a Detect e Improvement)

### 3.1 Línea de tiempo (hora de Chile)

| Fecha y hora | Evento | Fuente | Regla (nivel) |
|---|---|---|---|
| 04-11, 18:33:50 | `wevtutil cl Security` vacía el registro de Seguridad | Sysmon (proceso creado) | **Ninguna** |
| 04-11, 18:33:50 | Windows registra el evento 1102 | Seguridad | 63103 (5), MITRE T1070 |
| 04-11 | Búsquedas por `wevtutil` en Wazuh sin resultados: brecha confirmada | Wazuh | — |
| 04-11 a 05-11 | Se escribe la regla 100100, se valida con `wazuh-analysisd -t` y se reinicia Wazuh | Servidor Wazuh | — |
| 05-11, 16:01:54 | `wevtutil cl Application`: prueba de la nueva regla | Sysmon | **100100 (12)**, MITRE T1070.001 |

La alerta de la primera ejecución quedó marcada a las 18:27:55 y la de la segunda a las 16:00:46. El desfase con el evento original se debe a la diferencia de reloj entre el servidor y el endpoint (ver sección 5).

### 3.2 Hechos confirmados

| Hecho | Evidencia |
|---|---|
| Registro de Seguridad vaciado por `analista`, sesión `0x581ef` | Evento 1102 en la alerta 63103 (`subjectUserName`, `subjectLogonId`) |
| Sysmon registró `wevtutil.exe` aunque Wazuh no alertó | `Get-WinEvent` en el endpoint (captura 70) |
| Segundo borrado lanzado desde PowerShell, con integridad High, desde `C:\WINDOWS\system32\` | Alerta 100100: `parentImage`, `integrityLevel`, `currentDirectory` |
| Comando exacto | `"C:\WINDOWS\system32\wevtutil.exe" cl Application` |

### 3.3 Mapeo MITRE ATT&CK

| Táctica | Técnica | Observación |
|---|---|---|
| Defense Evasion | T1070.001 · Indicator Removal: Clear Windows Event Logs | La regla 63103 mapea al padre T1070; la sub-técnica la aporta la regla propia 100100 |

**Cambio de versión de ATT&CK.** En [ATT&CK v19](https://attack.mitre.org/resources/updates/updates-april-2026/) (abril de 2026) la táctica Defense Evasion se dividió en *Stealth* (TA0005) y *Defense Impairment* (TA0112), y **T1070.001 fue revocada**: la reemplaza [**T1685.005** · Disable or Modify Tools: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/), en la táctica Defense Impairment. Wazuh 4.14.9 y la regla 100100 usan todavía la numeración anterior (T1070 / T1070.001). La capa de MITRE Navigator del laboratorio usa la numeración actual (v20). Mejora propuesta: actualizar el mapeo de la regla propia cuando Wazuh adopte la v19 o superior.

### 3.4 Alcance y causa raíz
- **Alcance:** un equipo y un usuario. Se vaciaron dos registros: Seguridad (04-11) y Aplicación (05-11).
- **Qué se perdió:** el contenido local de esos registros. **Lo ya enviado al SIEM sigue disponible**, y por eso un SIEM central es clave frente a esta técnica.
- **Causa raíz (simulada):** el atacante ya tenía privilegios de administrador en el equipo. El vector inicial no se simula.
- **Causa de la detección débil:** las reglas de fábrica miran el resultado (evento 1102) y no el comando; además, ese evento existe solo para el registro de Seguridad.

### 3.5 Priorización
Borrar registros casi nunca ocurre en operación legítima y suele venir después de otras acciones del atacante. Impacto alto y atención inmediata, aunque el alcance sea un solo equipo.

## 4. Contención, erradicación y recuperación (equivale a Respond y Recover)

| Fase | Acción recomendada si fuera real | Hecho en el laboratorio |
|---|---|---|
| Contención | Tratar el equipo como comprometido y aislarlo; conservar la evidencia | No aplica: equipo de laboratorio |
| Análisis | Revisar en el SIEM la actividad anterior del mismo usuario y equipo: lo que se quiso ocultar ocurrió antes del borrado | Hecho en este informe: la línea de tiempo usa los eventos que llegaron al SIEM |
| Erradicación | Identificar quién y cómo obtuvo privilegios; revocar sesiones y rotar credenciales del usuario | No aplica |
| Mejora de detección | Cubrir el comando de borrado con una regla propia | **Regla 100100 creada, validada y probada** |
| Recuperación | Windows vuelve a registrar desde cero; el borrado no se puede deshacer | Sin impacto: la evidencia está en Wazuh y en las capturas |

## 5. Actividad posterior al incidente (equivale a Improvement)

### Lecciones aprendidas

| Hallazgo | Acción de mejora |
|---|---|
| El comando de borrado no tenía regla, aunque Sysmon lo registraba | Regla propia 100100 sobre `wevtutil cl` / `clear-log`, nivel 12. **Hecho** |
| La regla de fábrica deja el borrado en nivel 5 | La 100100 lo sube a 12, acorde con lo raro y grave de la actividad. **Hecho** |
| La 100100 no cubre `Clear-EventLog` ni `Remove-EventLog` de PowerShell | Regla equivalente para PowerShell. **Propuesta** |
| Desfase de reloj de 1 a 6 minutos entre el servidor Wazuh y el endpoint | Sincronizar ambos con NTP. **Propuesta** |
| El evento 1102 y el comando de Sysmon llegan como alertas separadas | Correlacionarlos en una sola alerta. **Propuesta** |

### Indicadores (del laboratorio)

| Tipo | Valor |
|---|---|
| Proceso | `C:\Windows\System32\wevtutil.exe` con argumento `cl` |
| Proceso padre | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Evento de Windows | 1102 (*The audit log was cleared*) |
| Sesión | `0x581ef` (usuario `analista`) |

### Regla creada

Archivo: [`reglas-wazuh/100100-wevtutil-borrado-registros.xml`](../reglas-wazuh/100100-wevtutil-borrado-registros.xml). Detalle de su construcción en [ATOMIC-003](../03-endpoint-windows/atomic-red-team/ATOMIC-003-T1070.001-borrado-registros.md).

## 6. Evidencia

Capturas en [`03-endpoint-windows/capturas/`](../03-endpoint-windows/capturas/):

| N° | Contenido |
|---|---|
| 67 | Número de eventos del registro de Seguridad antes de borrar |
| 68 | Registro de Seguridad tras el borrado, con el evento 1102 |
| 69 | Alerta 63103 por el evento 1102 |
| 70 | Sysmon sí registró `wevtutil` |
| 71 | Búsqueda en Wazuh sin alerta por `wevtutil`: la brecha |
| 72 | Regla 100100 escrita y configuración validada |
| 73 | Alerta de la regla 100100 con nivel 12 y MITRE T1070.001 |

## 7. Limitaciones del informe

- Incidente simulado: no hay atacante real ni vector inicial.
- La simulación fue manual porque no había prueba de Atomic Red Team para T1070.001 en la ruta estándar.
- Las horas de las alertas difieren del evento original por el desfase de reloj descrito.

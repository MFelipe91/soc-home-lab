# IR-001 · Persistencia en endpoint Windows (cuenta local + tarea programada)

> **Incidente simulado.** Los hechos provienen de pruebas con Atomic Red Team ejecutadas por mí en mi propio laboratorio. Este informe sigue el formato de [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (abril de 2025, alineada con CSF 2.0, reemplaza a la Rev. 2). Usa los nombres de fase clásicos y entre paréntesis la función de la Rev. 3 a la que equivalen.

## 1. Resumen ejecutivo

| | |
|---|---|
| **ID** | IR-001 |
| **Tipo de incidente** | Acceso persistente no autorizado (persistencia en un endpoint) |
| **Fecha** | 04-11-2026, hora de Chile (UTC-3) |
| **Activo afectado** | `WIN11-ENDPOINT` (192.168.56.30), sesión del usuario `analista`, integridad High |
| **Detectado por** | Wazuh 4.14.9 con Sysmon y registro de Seguridad de Windows |
| **Severidad** | Alta si fuera real (acceso persistente con privilegios altos). En el laboratorio, sin impacto |
| **Estado** | Cerrado. Cuenta y tarea eliminadas y verificadas |

Un atacante con acceso al equipo creó una cuenta local y una tarea programada para mantener el acceso. Wazuh alertó la cuenta con nivel 12. La tarea, en cambio, **no se vio** la primera vez porque Windows no auditaba su creación (brecha de visibilidad). Se activó la auditoría y la segunda ejecución sí fue detectada.

## 2. Preparación (equivale a Govern, Identify y Protect)

Lo que existía antes del incidente:
- Sysmon con la configuración de SwiftOnSecurity y agente Wazuh en el endpoint.
- Reglas de fábrica de Wazuh y el mapeo a MITRE ATT&CK.
- Registro de Seguridad de Windows enviado al SIEM.

Lo que **faltaba** y se descubrió durante el incidente:
- Auditoría de la subcategoría *Other Object Access Events* (evento 4698, tarea programada creada).
- Sin línea base de tareas programadas ni de cuentas locales.

## 3. Detección y análisis (equivale a Detect e Improvement)

### 3.1 Línea de tiempo (hora de Chile, 04-11-2026)

| Hora | Evento | Fuente | Regla (nivel) |
|---|---|---|---|
| 15:30:06 | `cmd.exe` → `net.exe` → `net1.exe user /add` crea la cuenta `T1136.001_CMD` | Sysmon | 92052 (4), 92036 (3), **92040 (12)** |
| 15:30:06 | Cuenta creada y asignada a grupos (eventos de Seguridad) | Seguridad | 60109, 60110 (8), 60160, 60170 (5) |
| 17:11 | `SCHTASKS /Create` crea la tarea `spawn`. Sysmon la registra, pero Windows **no** genera el evento 4698 | Sysmon | 92032 (3). **Sin alerta de Seguridad** |
| 17:44 | Auditoría activada y prueba repetida: la tarea se detecta con dos fuentes | Sysmon + Seguridad | 92032 (3) y **60228 (4)**, con 63 ms de diferencia |

### 3.2 Hechos confirmados

| Hecho | Evidencia |
|---|---|
| Cuenta local creada con contraseña en la línea de comandos | Campo `commandLine` de la alerta 92040 |
| Cadena de procesos PowerShell → cmd → net → net1, desde `...\AppData\Local\Temp\`, usuario `analista`, integridad High | Alerta 92040 |
| La cuenta existió de verdad | Eventos 60109/60110 del registro de Seguridad |
| Tarea `spawn` programada para ejecutar `cmd.exe` | Alerta 92032 (`schtasks /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe`) y `schtasks /Query` |
| Dos fuentes confirman la tarea (Sysmon y Seguridad) | Alertas 92032 y 60228 con 63 ms de diferencia |

### 3.3 Mapeo MITRE ATT&CK

| Táctica | Técnica | Observación |
|---|---|---|
| Persistence | T1136.001 · Create Account: Local Account | Regla 92040 |
| Persistence, Execution, Privilege Escalation | T1053.005 · Scheduled Task | La regla 60228 mapea al padre T1053; la sub-técnica la determina el analista leyendo el comando |

La regla 92032 también mapea a T1087 (descubrimiento de cuentas), que no describe esta actividad: es un mapeo genérico de la regla.

### 3.4 Falsos positivos descartados
Antes del ataque aparecieron unas 15 alertas de nivel 15 (regla 92213) y de auditoría CIS (19005 y 19014) causadas por la instalación de mis propias herramientas. No pertenecen al incidente.

### 3.5 Alcance y causa raíz
- **Alcance:** un solo equipo y un solo usuario (`analista`, sesión `0x581ef`). No se detectó movimiento lateral.
- **Causa raíz (simulada):** el atacante ya tenía ejecución en el equipo con privilegios altos. El vector inicial no se simula.
- **Causa de la detección tardía de la tarea:** falta de auditoría en Windows, no un fallo de Wazuh.

### 3.6 Priorización
Impacto potencial alto (acceso persistente con privilegios altos), alcance limitado (un equipo), recuperable (eliminar cuenta y tarea). Atención inmediata.

## 4. Contención, erradicación y recuperación (equivale a Respond y Recover)

Acciones recomendadas si fuera real, junto con lo que se hizo en el laboratorio:

| Fase | Acción recomendada | Hecho en el laboratorio |
|---|---|---|
| Contención | Aislar el equipo; deshabilitar la cuenta nueva y revisar sus grupos | No aplica: equipo de laboratorio |
| Erradicación | Eliminar la cuenta y la tarea; buscar otras persistencias (registro, servicios, otras cuentas) | Cuenta eliminada con `net user /del` y tarea con `SCHTASKS /Delete /TN spawn /F` |
| Verificación | Comprobar que ya no existen | `net user` y `schtasks /Query /TN spawn` confirmaron la limpieza |
| Credenciales | Tratar como expuesta la contraseña de la línea de comandos y rotar las del usuario `analista` | Credencial de prueba, sin valor real |
| Recuperación | Reactivar el equipo tras revisar | No aplica |

## 5. Actividad posterior al incidente (equivale a Improvement)

### Lecciones aprendidas

| Hallazgo | Acción de mejora |
|---|---|
| Windows no auditaba la creación de tareas programadas | Activar *Other Object Access Events* (`auditpol`) en la línea base de los endpoints. **Hecho** |
| La contraseña de la cuenta quedó en texto plano en el log | Limitar quién lee estos eventos; el triage con IA local (módulo 6) la oculta antes de analizar |
| Una tarea nueva genera solo nivel 4 aunque ejecute `cmd.exe` desde una ruta inusual | Regla propia que suba la severidad en ese caso. **Propuesta, no implementada** |
| Las alertas de nivel 3 y 4 por separado pasan desapercibidas | Correlacionar por equipo, usuario y ventana de segundos. **Propuesta** |
| El ruido de mis propias herramientas (nivel 15) tapa alertas reales | Excluir o etiquetar la actividad de herramientas de prueba |

### Indicadores de compromiso (del laboratorio)

| Tipo | Valor |
|---|---|
| Cuenta local | `T1136.001_CMD` |
| Tarea programada | `spawn` (ejecuta `C:\windows\system32\cmd.exe`) |
| Línea de comandos | `net1 user /add ...` y `SCHTASKS /Create /SC ONCE /TN spawn ...` |
| Directorio de trabajo | `C:\Users\analista\AppData\Local\Temp\` |

## 6. Evidencia

Informes técnicos: [ATOMIC-001](../03-endpoint-windows/atomic-red-team/ATOMIC-001-T1136.001-cuenta-local.md) y [ATOMIC-002](../03-endpoint-windows/atomic-red-team/ATOMIC-002-T1053.005-tarea-programada.md). Capturas en [`03-endpoint-windows/capturas/`](../03-endpoint-windows/capturas/):

| Capturas | Contenido |
|---|---|
| 52 a 55 | Cuenta creada y alertas 92040 y de Seguridad |
| 59 y 60 | Ejecución de la tarea y `schtasks /Query` |
| 61, 61b | Alertas de Sysmon por `schtasks.exe` |
| 62, 63 | Evento 4698 ausente: la brecha |
| 64 | Auditoría activada con `auditpol` |
| 65 | Alerta 60228 con MITRE |
| 66 | Limpieza |

## 7. Limitaciones del informe

- Incidente simulado: no hay atacante real, vector inicial ni impacto en datos.
- La hora de la primera tarea (17:11) viene del registro de la prueba; la alerta de Sysmon de esa ejecución está en la captura 61b.
- Hubo desfase de reloj entre el servidor Wazuh y el endpoint de entre 1 y 6 minutos (medido en el caso 7); las horas de alerta pueden diferir del evento original.

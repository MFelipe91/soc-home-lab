# INV-001 · Alerta de nivel 12 en el endpoint Windows (falso positivo)

| | |
|---|---|
| **Fecha del evento** | 03-11-2026, 01:33:22 |
| **Equipo** | `win11-endpoint` (agente 002, `192.168.56.30`) |
| **Regla de Wazuh** | 92058 · "Application Compatibility Database launched" · **nivel 12** |
| **Fuente** | Sysmon, Event ID 1 (creación de proceso) |
| **Técnica MITRE asociada** | Application Shimming (T1546.011), táctica Persistence. Confirmar en `rule.mitre.id` (captura 48). |
| **Resultado** | **Falso positivo.** Actividad normal de Windows. |

## 1. Contexto

Tras instalar el agente de Wazuh y reiniciarlo, el panel mostró varias alertas de nivel alto (9 y 12) que yo no había provocado. Las investigué antes de darlas por buenas.

## 2. Evidencia

| Campo | Valor |
|---|---|
| `data.win.eventdata.image` | `C:\Windows\System32\sdbinst.exe` |
| `data.win.eventdata.commandLine` | `sdbinst.exe -m -bg` |
| `data.win.eventdata.originalFileName` | `sdbinst.exe` |
| `data.win.eventdata.company` | Microsoft Corporation |
| `data.win.eventdata.description` | Application Compatibility Database Installer |
| `data.win.eventdata.fileVersion` | 10.0.26100.9818 |
| `data.win.eventdata.integrityLevel` | System |
| `data.win.eventdata.parentImage` | `C:\Windows\System32\svchost.exe` |
| `data.win.eventdata.parentCommandLine` | `svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc` |
| `data.win.eventdata.hashes` | Ver captura 48 (MD5, SHA256 e IMPHASH) |

## 3. Análisis

Qué haría sospechoso este evento: `sdbinst.exe` se usa en el ataque de *Application Shimming* para instalar una base de datos de compatibilidad (`.sdb`) maliciosa y conseguir persistencia.

Por qué aquí no lo es:

1. **Ruta legítima.** El binario está en `C:\Windows\System32`, no en una carpeta temporal o de usuario.
2. **Binario auténtico.** El `originalFileName` coincide con el nombre del archivo y la empresa es Microsoft. No está renombrado.
3. **Sin archivo `.sdb`.** La línea de comandos es `-m -bg` (mantenimiento en segundo plano). Un uso malicioso lleva la ruta a un `.sdb`.
4. **Proceso padre legítimo.** Lo lanzó `svchost.exe` con el servicio `PcaSvc` (Program Compatibility Assistant). Un ataque típico lo lanza desde `cmd.exe`, `powershell.exe` o un documento.
5. **Contexto.** Nivel de integridad `System`, y ocurrió justo después de instalar el agente y reiniciar, cuando Windows hace tareas de mantenimiento.

## 4. Conclusión

La alerta corresponde a mantenimiento normal del servicio de compatibilidad de Windows. **Se clasifica como falso positivo** y no requiere contención.

## 5. Lecciones

- El nivel de una alerta (aquí 12) indica qué tan sospechosa es la *técnica*, no si el evento es malicioso. Hay que mirar el contexto.
- Los campos que decidieron el caso fueron `commandLine`, `parentImage` y `integrityLevel`.
- Una buena regla de refinamiento sería excluir `sdbinst.exe -m -bg` cuando el padre sea `PcaSvc`, para bajar el ruido sin perder detección del uso malicioso.

## 6. Evidencia

- `capturas/48-m3-wazuh-alerta-nivel12-detalle.png`

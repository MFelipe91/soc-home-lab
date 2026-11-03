# SOC Home Lab

![Estado](https://img.shields.io/badge/estado-en%20progreso-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.14-005571)
![Endpoint](https://img.shields.io/badge/endpoint-Windows%2011%20%2B%20Sysmon-0078D4)
![Nessus](https://img.shields.io/badge/vuln%20scan-Nessus-00A9CE)
![Kali](https://img.shields.io/badge/attacker-Kali%20Linux-557C94)
![MITRE](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

Laboratorio personal donde practico el trabajo de un **analista SOC Nivel 1**: descubrir activos, evaluar vulnerabilidades, centralizar la telemetría de equipos Linux y Windows en un SIEM, detectar ataques mapeados a MITRE ATT&CK e investigar alertas. Cada módulo deja evidencia (capturas, salidas crudas e informes) para que cualquiera pueda revisar lo que hice.

> **English summary:** Personal SOC Level 1 home lab. Kali Linux attacks an intentionally vulnerable target inside an isolated network; findings are assessed with Nmap and Nessus (CVSS + EPSS). Logs from Linux agents, syslog sources and a Windows 11 endpoint (Sysmon) are centralized in Wazuh SIEM to detect and investigate attacks mapped to MITRE ATT&CK. Next: Microsoft Defender XDR and Microsoft Sentinel (KQL), Atomic Red Team simulations and AI-assisted alert triage.

**Autor:** Mario Felipe Busqués Araya · Ingeniero en Informática orientado a ciberseguridad

---

## Qué demuestra este laboratorio

| Habilidad | Dónde se ve |
|---|---|
| Diseño de un entorno aislado y seguro | [Módulo 0](#módulo-0--infraestructura) · [`docs/alcance.md`](docs/alcance.md) |
| Reconocimiento de red con Nmap | [Módulo 1](#módulo-1--reconocimiento-con-nmap) |
| Gestión de vulnerabilidades con Nessus y priorización CVSS vs EPSS | [Módulo 1b](#módulo-1b--evaluación-de-vulnerabilidades-con-nessus) |
| Despliegue y troubleshooting de un SIEM (Wazuh), agentes y syslog | [Módulo 2](#módulo-2--siem-con-wazuh) |
| Telemetría de endpoint Windows con Sysmon | [Módulo 3](#módulo-3--endpoint-windows-con-sysmon) |
| Detección de ataques con mapeo MITRE ATT&CK | [Casos de detección](#casos-de-detección) |
| Investigación y triage de alertas (falso positivo documentado) | [`INV-001`](03-endpoint-windows/investigaciones/INV-001-sdbinst-falso-positivo.md) |

## Arquitectura

![Topología del laboratorio](docs/topologia.png)

| Máquina | Rol | IP |
|---|---|---|
| Windows 11 (anfitrión) | VirtualBox 7.2 | 192.168.56.1 |
| Kali Linux | Atacante y analista (agente Wazuh) | 192.168.56.10 |
| Wazuh 4.14.9 | SIEM (manager, indexer y dashboard) | 192.168.56.20 |
| Windows 11 Enterprise (evaluación) | Endpoint con Sysmon y agente Wazuh | 192.168.56.30 |
| Metasploitable 2 | Objetivo vulnerable a propósito (envía logs por syslog) | 192.168.56.102 |

Red solo anfitrión `192.168.56.0/24`. La única excepción es el endpoint Windows, que tiene un segundo adaptador NAT de solo salida para los servicios en la nube de Microsoft. Reglas del laboratorio en [`docs/alcance.md`](docs/alcance.md).

## Avance

| Módulo | Contenido | Estado |
|---|---|---|
| 0 · Infraestructura | VirtualBox, red aislada, IPs fijas, instantáneas | ✅ |
| 1 · Reconocimiento | Nmap: hosts, servicios y los 65.535 puertos | ✅ |
| 1b · Vulnerabilidades | Nessus Essentials, CVSS v3 y EPSS | ✅ |
| 2 · SIEM | Wazuh, agente Linux, syslog, detección de fuerza bruta | ✅ |
| 3 · Endpoint Windows | Windows 11, Sysmon, agente Wazuh, investigación de alertas | ✅ |
| 4 · Microsoft | Defender for Endpoint y Microsoft Sentinel, reglas propias en KQL | ⏳ |
| 5 · Simulación de ataques | Atomic Red Team mapeado a MITRE ATT&CK | ⏳ |
| 6 · Triage con IA | Script que resume y clasifica alertas con validación humana | ⏳ |
| 7 · Informes | Informes de incidente NIST 800-61 y capa de MITRE Navigator | ⏳ |

---

## Módulo 0 · Infraestructura

Máquinas virtuales en una red solo anfitrión, con IP fija en Kali, Metasploitable aislada y una instantánea limpia de cada VM antes de empezar.

Evidencia: [`00-infraestructura/capturas/`](00-infraestructura/capturas/)

## Módulo 1 · Reconocimiento con Nmap

**Objetivo:** descubrir activos e identificar los servicios expuestos del objetivo.

1. Descubrimiento de hosts en la red (`nmap -sn`).
2. Servicios y versiones en los 1.000 puertos más comunes (`nmap -sV`).
3. Servicios en los 65.535 puertos (`nmap -sV -p- -T4`).

**Resultado:** 30 puertos abiertos agrupados en 9 hallazgos. El escaneo completo encontró el puerto **1524 (bind shell como root)**, que el escaneo de puertos comunes no detectó: por eso nunca hay que quedarse solo con los puertos por defecto.

![Escaneo de todos los puertos](01-vulnerabilidades/capturas/14-m1-nmap-todos-los-puertos.png)

- Comandos explicados: [`01-vulnerabilidades/comandos.md`](01-vulnerabilidades/comandos.md)
- Salida cruda (`.nmap`, `.gnmap`, `.xml`): [`01-vulnerabilidades/evidencias/`](01-vulnerabilidades/evidencias/)
- Informe: [`Informe_Nmap_Metasploitable.xlsx`](01-vulnerabilidades/informes/Informe_Nmap_Metasploitable.xlsx)

## Módulo 1b · Evaluación de vulnerabilidades con Nessus

**Objetivo:** pasar de "qué está expuesto" a "qué tan grave es" y priorizar.

Nessus Essentials 10.12.6, plantilla *Basic Network Scan*, sin credenciales, severidad en CVSS v3.0.

| Crítica | Alta | Media | Baja | Informativa | Total |
|:-:|:-:|:-:|:-:|:-:|:-:|
| 9 | 6 | 24 | 8 | 134 | 181 |

**Hallazgos clave**

- **Confirmados:** bind shell en el puerto 1524 (CVSS 9.8) y Ubuntu 8.04 sin soporte (CVSS 10.0).
- **Reclasificado:** Tomcat AJP (*Ghostcat*) estaba como Baja con Nmap y es **Crítica** (CVSS 9.8, EPSS 0.99).
- **Solo los vio Nessus:** VNC con contraseña `password`, SSL v2/v3, DROWN y Logjam.
- **Discrepancias a verificar:** Nessus no marcó la puerta trasera de vsftpd 2.3.4, UnrealIRCd ni distccd, que sí aparecen con Nmap. Un escaneo sin credenciales no prueba que algo sea seguro.

**Lección: CVSS no basta para priorizar.** Logjam tiene CVSS 3.7 (baja) pero EPSS 0.9986, la probabilidad de explotación más alta del escaneo. Por eso el informe cruza ambas métricas.

- Informe con comparación Nmap vs Nessus y priorización: [`Informe_Nessus_Metasploitable.xlsx`](01-vulnerabilidades/informes/Informe_Nessus_Metasploitable.xlsx)
- Evidencia de los 69 plugins: [`Nessus_M1b_Evidencia_Vulnerabilidades.pdf`](01-vulnerabilidades/evidencias/Nessus_M1b_Evidencia_Vulnerabilidades.pdf)

## Módulo 2 · SIEM con Wazuh

**Objetivo:** centralizar logs de distintos tipos de fuente y detectar ataques reales.

- **Servidor:** Wazuh 4.14.9 (OVA oficial) con IP fija `192.168.56.20` y disco ampliado a 80 GB.
- **Fuente con agente:** Kali Linux (`kali-atacante`), versión del agente igual a la del servidor.
- **Fuente sin agente:** Metasploitable 2 es demasiado antigua para el agente, así que reenvía su syslog por UDP 514. Wazuh solo acepta ese tráfico de `192.168.56.102` (`allowed-ips`).

![Detalle de alerta con técnica MITRE](02-siem-wazuh/capturas/27c-m2-wazuh-detalle-alerta-mitre.png)

Evidencia: [`02-siem-wazuh/capturas/`](02-siem-wazuh/capturas/) · [`02-siem-wazuh/evidencias/`](02-siem-wazuh/evidencias/)

## Módulo 3 · Endpoint Windows con Sysmon

**Objetivo:** obtener telemetría de un endpoint Windows como la que usa un SOC real.

- Windows 11 Enterprise (evaluación) con TPM 2.0 y Secure Boot, IP fija `192.168.56.30`.
- **Sysmon** (firma de Microsoft verificada) con la configuración de la comunidad SwiftOnSecurity.
- **Agente de Wazuh 4.14.9** (firma verificada) leyendo el canal `Microsoft-Windows-Sysmon/Operational`.

![Eventos de Sysmon en Wazuh](03-endpoint-windows/capturas/46-m3-wazuh-eventos-sysmon.png)

Evidencia: [`03-endpoint-windows/capturas/`](03-endpoint-windows/capturas/) · Investigación: [`INV-001`](03-endpoint-windows/investigaciones/INV-001-sdbinst-falso-positivo.md)

---

## Casos de detección

| # | Ataque o actividad | Origen → Destino | Regla(s) de Wazuh | MITRE ATT&CK | Evidencia |
|---|---|---|---|---|---|
| 1 | Fallos de login SSH repetidos | Windows anfitrión → Kali (agente) | 5760, 5557, 5503 y **2502** (nivel 10) | T1110 Brute Force (Credential Access) | [27c](02-siem-wazuh/capturas/27c-m2-wazuh-detalle-alerta-mitre.png) |
| 2 | Fuerza bruta SSH con Hydra | Kali → Metasploitable (syslog) | 2501 (x4, nivel 5) | T1110.001 Password Guessing | [30](02-siem-wazuh/capturas/30-m2-hydra-fuerza-bruta-exito.png) · [31](02-siem-wazuh/capturas/31-m2-hydra-alertas-wazuh.png) · [31b](02-siem-wazuh/capturas/31b-m2-hydra-detalle-regla-2501.png) |
| 3 | Reconocimiento del equipo (`whoami /all`, `ipconfig /all`, `net user`) | Endpoint Windows | 92031, 92033 (nivel 3) | Táctica Discovery | [46](03-endpoint-windows/capturas/46-m3-wazuh-eventos-sysmon.png) · [47](03-endpoint-windows/capturas/47-m3-wazuh-sysmon-detalle-comando.png) |
| 4 | Alerta de nivel 12 sin causa aparente | Endpoint Windows | 92058 (nivel 12) | T1546.011 Application Shimming | [INV-001](03-endpoint-windows/investigaciones/INV-001-sdbinst-falso-positivo.md): **falso positivo** |

**Hallazgos de analista**

- **Brecha de detección (caso 2):** la ráfaga rápida de Hydra disparó la regla base 2501, pero no la regla de correlación 2502 que sí se activó con intentos manuales más lentos. Además, 2501 no trae mapeo a MITRE. Un SIEM con reglas de fábrica no cubre todos los ritmos de ataque: hace falta afinar o escribir reglas propias.
- **Falso positivo documentado (caso 4):** una alerta de nivel 12 resultó ser mantenimiento normal de Windows. Se descartó con evidencia: ruta legítima, binario de Microsoft sin renombrar, proceso padre `PcaSvc` y ausencia de archivo `.sdb`.

---

## Problemas que resolví

| Problema | Causa | Solución |
|---|---|---|
| El panel de Wazuh no cargaba (índices en solo lectura) | El OVA trae un disco de 25 GB y el detector de vulnerabilidades lo llenó al 100% en el primer arranque | Reimportar, ampliar el disco a 80 GB antes de encender y crecer la partición con `growpart` y `xfs_growfs` |
| La IP de Wazuh podía cambiar | Estaba por DHCP | IP fija con `systemd-networkd`, con respaldo del archivo original |
| Wazuh no escuchaba syslog tras editar la configuración | `systemctl restart` no recargó `wazuh-remoted` | Reinicio con `wazuh-control restart` y verificación del puerto con `ss -ulnp` |
| Hydra y SSH fallaban contra Metasploitable | Su servidor SSH de 2008 solo ofrece algoritmos antiguos | Bloque específico para esa IP en `ssh_config` de Kali, sin debilitar el resto |
| El panel de Wazuh mostraba "Algo salió mal" | La traducción automática de Chrome rompe la interfaz React | Desactivar la traducción para ese sitio |
| La VM de Windows empezó a reinstalarse sola | Seguía conectado el disco de la instalación desatendida | Quitar la unidad óptica y restaurar la instantánea limpia |
| Nessus Essentials no permite exportar informes | Limitación de la licencia gratuita | Capturas de la vista completa y armado de un PDF de evidencia |
| El hash del instalador de Nessus no coincidía al pegarlo | El texto copiado venía corrupto | Verificación por captura de pantalla contra el hash oficial |

## Próximos pasos

1. **Microsoft Defender for Endpoint y Microsoft Sentinel** con el mismo endpoint, y reglas de detección propias en KQL.
2. **Atomic Red Team** para simular técnicas MITRE y comparar qué detecta cada herramienta.
3. **Triage asistido por IA:** script que resume una alerta, la mapea a MITRE y propone una respuesta, siempre con validación humana.
4. **Informes de incidente** en formato NIST 800-61 y capa de MITRE ATT&CK Navigator.

## Estructura del repositorio

```text
soc-home-lab/
├── docs/                       alcance y topología
├── 00-infraestructura/
│   └── capturas/
├── 01-vulnerabilidades/
│   ├── comandos.md             comandos explicados
│   ├── capturas/
│   ├── evidencias/             salida cruda de Nmap y PDF de Nessus
│   └── informes/               informes en Excel
├── 02-siem-wazuh/
│   ├── capturas/
│   └── evidencias/             reporte del agente en PDF
└── 03-endpoint-windows/
    ├── capturas/
    └── investigaciones/        INV-001: alerta investigada
```

## Aviso ético

Todo se ejecuta en máquinas propias, dentro de una red aislada creada para este fin. No uses estas técnicas contra sistemas sin autorización.

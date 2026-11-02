# SOC Home Lab

![Estado](https://img.shields.io/badge/estado-en%20progreso-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.14-005571)
![Nessus](https://img.shields.io/badge/vuln%20scan-Nessus-00A9CE)
![Kali](https://img.shields.io/badge/attacker-Kali%20Linux-557C94)
![MITRE](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

Laboratorio personal donde practico el trabajo de un **analista SOC Nivel 1**: descubrir activos, evaluar vulnerabilidades, centralizar logs en un SIEM y detectar ataques reales mapeados a MITRE ATT&CK. Cada módulo deja evidencia (capturas, salidas crudas e informes) para que cualquiera pueda revisar lo que hice.

> **English summary:** Personal SOC Level 1 home lab. Kali Linux attacks an intentionally vulnerable target inside an isolated network; findings are assessed with Nmap and Nessus (CVSS + EPSS), and logs are centralized in Wazuh SIEM to detect and investigate attacks mapped to MITRE ATT&CK.

**Autor:** Mario Felipe Busqués Araya · Ingeniero en Informática orientado a ciberseguridad

---

## Qué demuestra este laboratorio

| Habilidad | Dónde se ve |
|---|---|
| Diseño de un entorno aislado y seguro | [Módulo 0](#módulo-0--infraestructura) · [`docs/alcance.md`](docs/alcance.md) |
| Reconocimiento de red con Nmap | [Módulo 1](#módulo-1--reconocimiento-con-nmap) |
| Gestión de vulnerabilidades con Nessus y priorización CVSS vs EPSS | [Módulo 1b](#módulo-1b--evaluación-de-vulnerabilidades-con-nessus) |
| Despliegue y troubleshooting de un SIEM (Wazuh) | [Módulo 2](#módulo-2--siem-con-wazuh-en-curso) |
| Documentación e informes profesionales | Carpetas `informes/` de cada módulo |

## Arquitectura

![Topología del laboratorio](docs/topologia.png)

| Máquina | Rol | IP |
|---|---|---|
| Windows 11 (anfitrión) | VirtualBox 7.2 | 192.168.56.1 |
| Kali Linux | Atacante y analista | 192.168.56.10 |
| Wazuh 4.14.9 | SIEM (manager, indexer y dashboard) | 192.168.56.20 |
| Metasploitable 2 | Objetivo vulnerable a propósito | 192.168.56.102 |

Red solo anfitrión `192.168.56.0/24`, sin salida a internet para los objetivos. Reglas del laboratorio en [`docs/alcance.md`](docs/alcance.md).

## Avance

| Módulo | Contenido | Estado |
|---|---|---|
| 0 · Infraestructura | VirtualBox, red aislada, IPs fijas, instantáneas | ✅ |
| 1 · Reconocimiento | Nmap: hosts, servicios y los 65.535 puertos | ✅ |
| 1b · Vulnerabilidades | Nessus Essentials, CVSS v3 y EPSS | ✅ |
| 2 · SIEM | Wazuh, agentes Linux y Windows, syslog | 🔄 |
| 3 · Active Directory | Controlador de dominio y endpoint Windows con Sysmon | ⏳ |
| 4 · Detección | 8 ataques simulados mapeados a MITRE ATT&CK | ⏳ |
| 5 · Respuesta | Informes de incidente NIST 800-61, Active Response | ⏳ |

---

## Módulo 0 · Infraestructura

Dos máquinas virtuales en una red solo anfitrión, con IP fija en Kali, Metasploitable aislada y una instantánea limpia de cada VM antes de empezar.

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

## Módulo 2 · SIEM con Wazuh (en curso)

Wazuh 4.14.9 (OVA oficial) con IP fija `192.168.56.20`. Próximos pasos: agente en Kali, logs de Metasploitable por syslog y endpoint Windows con Sysmon.

---

## Problemas que resolví

| Problema | Causa | Solución |
|---|---|---|
| El panel de Wazuh no cargaba (índices en solo lectura) | El OVA trae un disco de 25 GB y el detector de vulnerabilidades lo llenó al 100% en el primer arranque | Reimportar, ampliar el disco a 80 GB antes de encender y crecer la partición con `growpart` y `xfs_growfs` |
| La IP de Wazuh podía cambiar | Estaba por DHCP | IP fija con `systemd-networkd`, con respaldo del archivo original |
| Nessus Essentials no permite exportar informes | Limitación de la licencia gratuita | Capturas de la vista completa y armado de un PDF de evidencia |
| El hash del instalador de Nessus no coincidía al pegarlo | El texto copiado venía corrupto | Verificación por captura de pantalla contra el hash oficial |

## Estructura del repositorio

```text
soc-home-lab/
├── docs/                       alcance y topología
├── 00-infraestructura/
│   └── capturas/
└── 01-vulnerabilidades/
    ├── comandos.md             comandos explicados
    ├── capturas/
    ├── evidencias/             salida cruda de Nmap y PDF de Nessus
    └── informes/               informes en Excel
```

## Aviso ético

Todo se ejecuta en máquinas propias, dentro de una red aislada creada para este fin. No uses estas técnicas contra sistemas sin autorización.

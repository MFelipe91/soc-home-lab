# Alcance y reglas del laboratorio

- Red solo anfitrión `192.168.56.0/24` para toda la comunicación interna del laboratorio.
- Activos:
  - Kali Linux: `192.168.56.10` (atacante y analista)
  - Wazuh: `192.168.56.20` (SIEM)
  - Windows 11 Enterprise (evaluación): `192.168.56.30` (endpoint con Sysmon y agente de Wazuh)
  - Metasploitable 2: `192.168.56.102` (objetivo vulnerable)
- **Excepción controlada:** el endpoint Windows 11 tiene un segundo adaptador NAT, solo de salida, porque Microsoft Defender y Sentinel necesitan internet. Metasploitable 2 nunca tiene salida a internet.
- Todo se ejecuta sobre máquinas propias creadas para este laboratorio.
- Prohibido escanear o atacar redes o equipos que no sean del laboratorio.
- El SIEM mantiene credenciales de fábrica por estar aislado; nunca se conecta a una red externa.
- Las reglas de firewall que permiten ping (`Lab ICMP`) existen solo en las máquinas del laboratorio, nunca en el equipo anfitrión.
- No se publican contraseñas, códigos de activación ni datos personales en las capturas.

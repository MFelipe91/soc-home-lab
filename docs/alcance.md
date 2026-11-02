# Alcance y reglas del laboratorio

- Red aislada solo anfitrión `192.168.56.0/24`, sin salida a internet para los objetivos.
- Activos:
  - Kali Linux: `192.168.56.10` (atacante y analista)
  - Wazuh: `192.168.56.20` (SIEM)
  - Metasploitable 2: `192.168.56.102` (objetivo vulnerable)
- Todo se ejecuta sobre máquinas propias creadas para este laboratorio.
- Prohibido escanear o atacar redes o equipos que no sean del laboratorio.
- El SIEM mantiene credenciales de fábrica por estar aislado; nunca se conecta a una red externa.
- No se publican contraseñas, códigos de activación ni datos personales en las capturas.

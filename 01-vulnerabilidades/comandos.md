# Comandos usados en el Módulo 1

Todos se ejecutan desde Kali (192.168.56.10) contra el laboratorio aislado.

## 1. Descubrimiento de hosts

```bash
nmap -sn -oN /home/kali/lab/nmap/01-descubrimiento.txt 192.168.56.0/24
```

| Parte | Qué hace |
|---|---|
| `-sn` | Solo descubre qué equipos están vivos. No escanea puertos |
| `-oN <archivo>` | Guarda la salida en formato normal, legible (un solo archivo `.txt`) |
| `192.168.56.0/24` | Toda la red del laboratorio (254 direcciones posibles) |

## 2. Servicios y versiones

```bash
nmap -sV -oA /home/kali/lab/nmap/02-servicios-metasploitable 192.168.56.102
```

| Parte | Qué hace |
|---|---|
| `-sV` | Detecta qué servicio y qué versión corre en cada puerto abierto |
| `-oA <nombre>` | Guarda la salida en 3 formatos a la vez: `.nmap` (legible), `.gnmap` (para grep) y `.xml` (para otras herramientas) |
| `192.168.56.102` | Objetivo: Metasploitable 2 |

Sin `-p`, Nmap revisa solo los 1.000 puertos más comunes.

## 3. Todos los puertos

```bash
nmap -sV -p- -T4 -oA /home/kali/lab/nmap/03-todos-los-puertos 192.168.56.102
```

| Parte | Qué hace |
|---|---|
| `-p-` | Revisa los 65.535 puertos, no solo los comunes |
| `-T4` | Velocidad agresiva. Aceptable en un laboratorio, ruidosa en una red real |

**Por qué hacer los dos:** el escaneo 3 encontró puertos que el 2 no vio, entre ellos el 1524 (bindshell). Un escaneo de puertos comunes habría dejado pasar la puerta trasera más grave.

## 4. Traer la evidencia a Windows

```powershell
scp "kali@192.168.56.10:~/lab/nmap/*" "D:\SOC-Lab\evidencias\m1-vulnerabilidades\"
```

`scp` copia archivos por SSH (cifrado), de Kali al equipo anfitrión.

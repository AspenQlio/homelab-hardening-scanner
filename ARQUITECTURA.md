# 🛡️ Homelab Hardening Scanner: Arquitectura Definitiva

> Documento de diseño técnico aprobado por Aspen. 
> Objetivo: Crear el escáner de seguridad automatizado definitivo para el portafolio.

## 🏗️ MÓDULOS DEL ESCÁNER

### 1. Módulo de Red y Firewall (`firewall_auditor.py`)
- **Misión:** Garantizar que el servidor no está expuesto.
- **Acciones:** 
  - Detectar si `ufw`, `iptables` o `firewalld` están activos.
  - Verificar que la regla por defecto de entrada (INPUT) sea `DROP`.
  - Alertar sobre puertos peligrosos abiertos (ej. 21 FTP, 23 Telnet).

### 2. Módulo de Accesos y Privilegios (`identity_auditor.py`)
- **Misión:** Cazar usuarios fantasma y escaladas de privilegios.
- **Acciones:**
  - Leer `/etc/shadow` y buscar cuentas de sistema (que no sean root) con contraseñas habilitadas.
  - Leer el grupo `wheel` o `sudo` en `/etc/group` y listar quién tiene poder absoluto.
  - Verificar permisos del archivo `/etc/sudoers` (debe ser `0440`).

### 3. Módulo de Superficie Docker (`docker_auditor.py`)
- **Misión:** Prevenir escapes de contenedores.
- **Acciones:**
  - Leer los integrantes del grupo `docker` (cualquiera aquí es un riesgo potencial de root).
  - Listar contenedores corriendo en modo `--privileged` (peligro altísimo).
  - Revisar si el daemon expone el puerto `2375` sin encriptación.

### 4. Módulo de Salud del Sistema (Zombies & Updates) (`health_auditor.py`)
- **Misión:** Asegurar que los parches están aplicados.
- **Acciones:**
  - Comprobar si hay paquetes huérfanos o actualizaciones críticas de seguridad pendientes (`pacman -Qu`).
  - Detectar si hace falta un reinicio tras actualizar el Kernel (leyendo `/boot` vs `uname -r`).

### 5. Motor de Reportes Multiformato (`reporter.py`)
- **Misión:** Mostrar la información de manera profesional.
- **Formatos de Salida:**
  - **Terminal Interactiva:** Usando `Rich` para mostrar tablas de colores (Verde = Pass, Rojo = Fail).
  - **Exportación Markdown:** Genera un archivo `audit_YYYYMMDD.md` listo para pegar en GitHub o Notion.

---
*Diseñado por Santi & Aspen.*

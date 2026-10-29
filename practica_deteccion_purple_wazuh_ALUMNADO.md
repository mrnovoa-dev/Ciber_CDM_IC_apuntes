# Práctica · Detección defensiva purple team con Wazuh

Oct 29, 2026 · @María RN

## Datos de la práctica

En esta práctica vais a detectar tres ataques reales lanzados dentro de un laboratorio aislado, escribir la regla que los caza en el SIEM y documentar el incidente. Se trabaja en parejas con dos roles que se intercambian: equipo rojo (ataca) y equipo azul (detecta). El enfoque purple team hace que cada ataque termine en una detección y una regla nueva.

| Campo | Valor |
| --- | --- |
| Módulo | MP5021 Incidentes de Ciberseguridade |
| Duración | 4 horas (2 sesiones de 2 h) |
| Agrupamiento | Parejas, roles rojo/azul intercambiables |
| Laboratorio | labcyber, red interna aislada 172.21.10.0/24 (VirtualBox o Proxmox) |
| Entrega | Informe por pareja + capturas + reglas creadas |

**Objetivos.** Al terminar, seréis capaces de: comprobar que la telemetría llega al SIEM; reconocer en los registros la huella de un ataque de fuerza bruta, de ejecución de código desde Office y de persistencia; escribir una regla de detección en Wazuh y mapearla a MITRE ATT\&CK; y clasificar y notificar el incidente según la Guía Nacional de Gestión de Ciberincidentes.

## Escenario

**TecnoMariña S.L.** es una pyme gallega ficticia con un servidor web y SSH en su red interna y puestos Windows para el personal. Su SIEM (Wazuh) recoge los registros de todos los equipos. Un atacante ya ha conseguido entrar en la red interna y lanza varios ataques desde una máquina Kali. El equipo azul (el SOC de la empresa) tiene que detectarlos a tiempo.

Todo ocurre en la red interna aislada **labcyber (172.21.10.0/24)**, sin salida a internet, de modo que los ataques son reales pero no salen del laboratorio.

![Laboratorio labcyber: 4 VM en la red aislada 172.21.10.0/24](diagrama_red.png)

*Laboratorio labcyber · 4 VM en la red aislada 172.21.10.0/24*

| VM | IP | Rol en la práctica |
| --- | --- | --- |
| siem | 172.21.10.10 | SIEM Wazuh: recibe logs, correla y alerta (equipo azul) |
| win10 | 172.21.10.20 | Puesto víctima: recibe el phishing y ejecuta la macro |
| srvweb | 172.21.10.30 | Servidor web/SSH víctima: sufre la fuerza bruta |
| kali | 172.21.10.100 | Máquina del atacante (equipo rojo) |

**Roles.** El *equipo rojo* ejecuta los ataques desde Kali siguiendo el guion. El *equipo azul* trabaja en el panel de Wazuh: observa, investiga y escribe las reglas. A mitad de práctica intercambiad los roles para pasar por los dos lados.

## Fase 0. Preparación y comprobación de la telemetría

Antes de atacar nada, el equipo azul comprueba que el SIEM está recibiendo datos. Sin telemetría no hay detección posible: es el punto de partida de todo el módulo.

1. Arrancad las cuatro VM del laboratorio y comprobad que se ven entre sí con `ping` dentro de 172.21.10.0/24.
2. En el SIEM, abrid el panel de Wazuh (reenvío de puertos NAT: `https://localhost:8443` desde el anfitrión).
3. Confirmad en *Agents* que win10 y srvweb aparecen como **Active**. Si alguno está desconectado, revisad el servicio del agente antes de seguir.
4. Generad un evento de prueba y vedlo llegar:
   - En srvweb, haced un intento de login fallido por SSH a propósito.
   - En el panel, buscad ese evento en *Security events* y anotad el campo que lo identifica (regla, nivel, IP de origen).

**Pregunta de control.** ¿Qué campos del evento permiten saber qué equipo lo generó y desde dónde? Anotadlos: los vais a usar en todas las reglas.

> Nota de seguridad: todos los ataques de esta práctica se lanzan únicamente contra las VM del laboratorio y dentro de su red aislada. No se atacan equipos reales ni del centro ni de internet.

## Fases 1 a 3. Tres ataques, tres detecciones

Cada ejercicio sigue el mismo ciclo purple team: el rojo ataca, el azul lo ve en el SIEM, escribe o ajusta la regla y lo mapea a MITRE ATT&CK. Dedicad unos 40 minutos a cada uno. La regla la escribís vosotros en `/var/ossec/etc/rules/local_rules.xml`; usad los campos que localicéis en cada fase.

### Fase 1. Fuerza bruta SSH contra el servidor

**Ataque (rojo).** Desde Kali, lanzad un ataque de diccionario contra el SSH de srvweb:

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://172.21.10.30 -t 4
```

**Detección (azul).** En el panel, buscad los eventos de autenticación de srvweb. Veréis muchos fallos seguidos (`sshd: authentication failure`) desde una misma IP y, si el diccionario acierta, un acceso correcto justo después.

- ¿Qué reglas trae Wazuh ya para intento fallido y para fuerza bruta? Comprobad que saltan y anotad sus números.
- Localizad el campo de la IP de origen y el usuario objetivo.

**Vuestra regla.** Escribid una regla local que suba el nivel y añada una etiqueta propia cuando haya fuerza bruta desde la red interna, apoyándoos en la regla genérica de fuerza bruta. Reiniciad el servicio, repetid el ataque y confirmad que salta vuestra regla.

**ATT&CK.** Identificad la técnica de la matriz que corresponde a un ataque de fuerza bruta.

### Fase 2. Ejecución de PowerShell desde un documento de Office

**Ataque (rojo).** Simulad el phishing: en win10, abrid un documento de Word con una macro que lanza PowerShell (el guion del rojo lo entrega por el laboratorio de correo aislado). La macro ejecuta algo como:

```
powershell -nop -w hidden -enc <comando codificado en base64>
```

**Detección (azul).** Con Sysmon en win10, el evento de creación de proceso muestra qué proceso es el padre de `powershell.exe`. Una ofimática lanzando una shell casi nunca es legítimo.

- Buscad en el panel los eventos de Sysmon de win10 y localizad los campos del proceso padre y de la línea de comandos.
- ¿Qué tres indicadores hacen sospechoso este proceso? (Pista: quién lo lanza, la ventana y la codificación del comando.)

**Vuestra regla.** Escribid una regla que detecte que Word o Excel lanzan PowerShell, usándo los campos de proceso padre e imagen.

**ATT&CK.** Identificad las técnicas de phishing con adjunto y de ejecución por PowerShell.

### Fase 3. Persistencia en el equipo comprometido

**Ataque (rojo).** Desde la sesión obtenida en win10, cread persistencia con una tarea programada o una clave de registro de arranque:

```
schtasks /create /tn ActualizadorSistema /tr "powershell -nop -w hidden -c IEX(...)" /sc onlogon
```

**Detección (azul).** El evento muestra la creación de la tarea o la modificación de la clave de arranque. Lo sospechoso es el nombre que imita a algo del sistema y que ejecuta PowerShell oculto.

- Buscad los eventos de creación de tareas programadas en win10.
- Relacionadlos con la sesión de la fase 2: ¿es el mismo atacante?

**Vuestra regla.** Escribid una regla que alerte de tareas programadas que ejecutan PowerShell.

**ATT&CK.** Identificad la técnica de tarea programada. Con esto habréis cubierto tres fases de la cadena de ataque: acceso, ejecución y persistencia.

## Fase 4. Gestión del incidente, CVE/CVSS y notificación

Detectar es solo la mitad. Ahora tratad los tres ataques como un único incidente y gestionadlo de principio a fin, que es el núcleo del módulo.

1. **Reconstruid la línea temporal.** Ordenad los eventos de las tres fases: fuerza bruta, ejecución de la macro y persistencia. Mostrad que es un solo atacante avanzando por la red.
2. **Clasificad.** Asignad tipo y peligrosidad según la taxonomía de la Guía Nacional de Notificación y Gestión de Ciberincidentes. Justificad el nivel por el impacto en confidencialidad, integridad y disponibilidad.
3. **Vinculad una vulnerabilidad.** Si el acceso inicial se aprovechó de un servicio sin parchear, buscad su **CVE** y leed o calculad su **CVSS**. Anotad el vector CVSS y la nota base.
4. **Contened y erradicad.** Proponed acciones: bloquear la IP del atacante, deshabilitar la cuenta usada, eliminar la tarea programada y restaurar el equipo.
5. **Notificad.** Indicad a qué CERT correspondería y en qué plazo, teniendo en cuenta los plazos vigentes de RGPD y de la directiva NIS2.
6. **Lecciones aprendidas.** ¿Qué reglas faltaban? ¿Qué se podría haber detectado antes? Aquí se cierra el ciclo: las reglas que habéis creado en las fases 1 a 3 son la mejora concreta.

**Mini-ejercicio de CVSS.** Dado el vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, decid qué nota da y explicad por qué. Luego cambiad `AV:N` por `AV:L` y comentad cómo baja la nota y por qué.

## Entregables y rúbrica

Cada pareja entrega un **informe de incidente** (3 a 5 páginas) con: la línea temporal de los tres ataques, una captura por cada detección, las tres reglas que habéis creado con su mapeo ATT&CK, la clasificación y el CVE/CVSS asociado, y las acciones de contención y notificación propuestas.

| Criterio | Peso | Qué se valora |
| --- | --- | --- |
| Telemetría y detección | 25% | Los tres ataques se localizan en el SIEM con los campos correctos |
| Reglas y ATT&CK | 25% | Las reglas funcionan y están bien mapeadas a las técnicas |
| Gestión del incidente | 25% | Línea temporal, clasificación y contención coherentes |
| CVE/CVSS y notificación | 15% | Vulnerabilidad bien identificada y notificación correcta |
| Informe | 10% | Claro, ordenado y con evidencias |

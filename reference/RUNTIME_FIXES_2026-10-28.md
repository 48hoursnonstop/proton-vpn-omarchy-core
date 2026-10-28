# Implementación de las correcciones — 28 de octubre de 2026

Esta revisión parte del núcleo 0.9.10 (`49ac4811718f32d19c1785efcd9320baa6ccadb0`)
y del plugin instalado (`7f48b37b59d4a4496bf20907daf5468653a6310c`). Es una
compilación local de un proyecto independiente de Proton. No es una publicación
oficial ni una declaración de paridad completa con Windows.

## Cambios de funcionamiento y seguridad

- **Split tunneling IPv6:** el UID, la clave IPv6 y el buffer de marca ya no se
  sobrescriben en la pila eBPF.
- **UDP con varios destinos:** cada envío recalcula su marca desde la política
  actual de la aplicación. Una excepción anterior de IP, LAN o DNS no conserva
  el bypass para un destino distinto. Se preservan las marcas ajenas al proyecto.
- **Qt 6.12:** el plugin usa explícitamente `Commons.Color`, evitando la colisión
  que devolvía colores indefinidos en el shell actual.
- **Instalación en Arch actual:** el hook reconoce las dos rutas oficiales de
  ProTun (`/usr/lib/` y `/usr/libexec/`) y continúa rechazando rutas arbitrarias.
  La normalización y su retirada se verifican con archivos desechables.
- **Observación continua:** el agente comprueba el estado del túnel cada dos
  segundos aunque el panel esté cerrado. Una caída inesperada de un túnel propio
  activa la recuperación existente, con límites y cancelación. Una desconexión
  manual o una VPN externa no inicia esta recuperación.
- **Cerrar sesión sin red:** registra primero la prohibición de reimportación y
  retira la sesión privada local; la revocación remota tiene un máximo de cinco
  segundos. No borra credenciales compartidas de Proton ni cambia el formato del
  keyring.
- **Datos remotos:** renueva plan/configuración cada quince minutos y permite
  actualizar manualmente desde Cuenta. La configuración ausente o caducada se
  vuelve a solicitar antes de conectar. Conserva una configuración utilizable si
  falla la red. La ubicación física se invalida al cambiar la red y se consulta
  únicamente sin VPN; no se etiqueta una IP de salida VPN como IP física.

## Guest Hole mediante Stealth

El usuario autorizó incluir esta función. Con Enrutamiento alternativo activado,
un fallo de transporte en una operación de inicio de sesión, actualización manual
de cuenta o preparación de conexión puede abrir un túnel temporal ProTun TLS en
443. Los procesos de mantenimiento, las lecturas de ubicación y cerrar sesión no
lo activan.

Se utilizan hasta cinco candidatos: servidores directos del catálogo firmado
validado y servidores bootstrap públicos del cliente oficial Android. El asset
está fijado en el código con su hash y procedencia en `NOTICE.md`; no se descargan
claves ni ejecutables desde una fuente nueva. Se genera una clave WireGuard
aleatoria para cada perfil y se mantienen las comprobaciones TLS/PKI y los pins
del API. DNS y solicitudes de recuperación se vinculan a la interfaz temporal.

La recuperación es cancelable desde la interfaz de autenticación o el panel.
El trabajador conserva la exclusión mutua hasta terminar la activación y retirar
su UUID exacto, incluso si desaparece el solicitante. La conexión normal espera
esa limpieza. El arranque también retira perfiles temporales propios que hayan
quedado después de una interrupción.

El túnel temporal no aparece como sesión autenticada o estado Protegido. No
sustituye una VPN existente ni desactiva un kill switch que bloquee la red.
**El motor oficial Linux instala rutas temporales de túnel completo**: durante
la recuperación puede interrumpirse brevemente otro tráfico IPv4. El perfil usa
temporalmente el DNS del túnel y no se configura para conexión automática. La
prueba real encontró que NetworkManager omite listas DNS vacías y ProTun exige
ese campo; se conserva por ello la entrada DNS normal de Proton (`10.2.0.1`).

La interfaz ProTun v1 instalada no admite el campo de relay/bouncing de los
clientes recientes. Se omiten entradas bootstrap sin `EntryIP` directo. Esta
implementación cubre Stealth directo; no afirma soporte de relays v2, fallback
Guest Hole OpenVPN ni disponibilidad frente a Fortinet.

## Validación y límites

- Rust: 172 pruebas aprobadas, cero fallos; nueve pruebas opt-in omitidas en la
  ejecución normal (incluido el nuevo verificador del kernel).
- Las regresiones eBPF ejecutan las instrucciones reales generadas con mapas y
  helpers simulados: claves IPv6, alternancia UDP, política de aplicación,
  excepciones LAN/DNS y preservación de marcas externas.
- La prueba existente de rutas IPv4/IPv6 y kill switch pasa dentro de un
  namespace de red desechable, sin modificar las rutas de la sesión del usuario.
- Los fixtures QML comprueban navegación, idioma, foco, cancelación, recuperación
  del keyring, estados de controles, tráfico, movimiento y contrato de interfaz.
  El host nativo se verifica cerrado; el instalador usa un fixture independiente.
- La compilación optimizada del agente y splitd termina correctamente, con las
  dependencias bloqueadas y sin acceso a la red para Cargo.
- La prueba eBPF opcional carga programas y mapas de prueba en el kernel **sin
  adjuntarlos a ningún cgroup**. Su ejecución con permisos se registra por
  separado junto al paquete local.

No se intentan conexiones VPN reales desde la red protegida por Fortinet, ni
se envían reportes de soporte/telemetría. Quedan pendientes las pruebas reales
de acceso Guest Hole, reconexión, entrega de paquetes UDP alternando destinos,
familias IPv4/IPv6 y coexistencia con kill switch. Las pruebas de lógica y
verificador no sustituyen esas pruebas de integración.

Los primeros fallos de workspace/teclado de la auditoría se debían parcialmente
a reentrada del Timer dentro de los bucles de eventos de QtTest. Los fixtures
ahora suspenden su Timer durante cada fase. El fallo de `Color` sí se confirmó
en el shell real y se corrigió en el código de producción.

## Alcance frente a Windows

La comparación usa la versión pública 5.1.8 y las fuentes oficiales revisadas el
28 de octubre, no funciones futuras anunciadas. Se corrigen carencias de
observación, renovación y recuperación. Los controladores TAP, el actualizador
de Windows y su marco de ventana no son funciones trasladables directamente al
plugin Omarchy.

Los reportes automáticos de fallos permanecen deshabilitados por decisión de
producto. Los idiomas actuales siguen siendo español e inglés. Si se amplían,
portugués y francés son propuestas razonables, sujetas a revisión humana de las
traducciones; no se presentan como una prioridad basada en datos de usuarios.

## Fuentes y procedencia

- [Windows: fuentes oficiales](https://github.com/ProtonVPN/win-app)
- [Bootstrap Android fijado](https://github.com/ProtonVPN/android-app/blob/deb11fef4092a1ecfcf51a7d40bdece9eb4c3e5e/app/src/main/assets/GuestHoleServers.json)
- [ProTun Linux: servicio y contrato de perfiles](https://github.com/ProtonVPN/python-proton-vpn-api-core/tree/1829b00a27071ae3a3ad3f6c791add88c5c6eaec/src/protun/nm_protun_service)

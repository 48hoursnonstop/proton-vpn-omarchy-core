# Revisión de Proton VPN Windows — 2026-09-22

> Historical audit of 0.9.7 before implementation. See
> [implementation and validation status](WINDOWS_PARITY_IMPLEMENTATION_2026-09-22.md)
> for the subsequent parity branch.


## Alcance y resultado

Hay trabajo de compatibilidad y producto pendiente. La prioridad es validar
los endpoints antes de seleccionarlos/conectarlos; siguen ciudades duplicadas
y la información de Smart Routing. No se encontró un cambio del contrato de
autenticación que exija modificar el formato privado del keyring.

Comparación de código:

- Referencia congelada: Windows `4d9ac60d1db5d3f2908498470a9d1646723afcfd`
  (`5.1.5`, commit del 2 de julio).
- Revisado: `master` / `v5.1.8`,
  `d2a4f8bc92a0fd296943a7cdd15f4f870c8a87f9` (commit del 28 de agosto).
- Diferencia: **58 commits y 412 rutas modificadas**. Se obtuvo la lista
  completa mediante Git; el endpoint de comparación de GitHub truncaba a 300.
- Core local y remoto: `7f1d2bf51359a799ed1c1fcfc609291cdcd4aad4`, `0.9.7`.
- Frontend local y remoto: `119732780919773cf51ae6234e438242137cb216`, `0.9.7`.
- Paquete instalado: `proton-vpn-omarchy 0.9.7-2`.
- Dependencia Linux instalada: `python-proton-vpn-api-core 5.6.10-1`, frente
  a `5.5.11-1` en nuestra matriz histórica de agosto.

Las releases [5.1.6](https://github.com/ProtonVPN/win-app/releases/tag/v5.1.6),
[5.1.7](https://github.com/ProtonVPN/win-app/releases/tag/v5.1.7) y
[5.1.8](https://github.com/ProtonVPN/win-app/releases/tag/v5.1.8) se publicaron
en GitHub el **22 de septiembre**. Esa fecha no es la fecha de sus commits ni
demuestra cuándo comenzaron a distribuirse mediante otros canales.

Revisión dirigida de los cambios funcionales, sus llamadas y equivalentes
locales; los cambios binarios de ProTun no se reconstruyeron ni auditaron
internamente. No se hicieron conexiones VPN, pruebas de suspensión, cambios
de rutas, lecturas de credenciales ni instalaciones durante esta revisión.

## Hallazgos para nuestro proyecto

### 1. Prioridad alta: falta validación de endpoints en el core

Windows extiende el validador existente a la selección y al inicio del túnel
en [27bd6b78](https://github.com/ProtonVPN/win-app/commit/27bd6b786d4d6a0067e6d95ecf1c00aa1d058ff3).
Su [ServerValidator](https://github.com/ProtonVPN/win-app/blob/d2a4f8bc92a0fd296943a7cdd15f4f870c8a87f9/src/ProtonVPN.Vpn/ServerValidation/ServerValidator.cs)
comprueba la forma de la clave X25519 y una firma Ed25519 del objeto que
contiene `EntryIP` y `Label`, usando una clave oficial configurada. La firma
no debe describirse como si cubriera todos los campos del servidor.

En nuestro `agent/src/native_backend/catalog.rs`, `ServerCatalog::select`
solo exige endpoint y clave no vacíos para el servidor físico. `Signature`
queda dentro de `PhysicalServer.extra` y no se verifica. `network.rs` entrega
endpoint y clave al servicio ProTun sin esta comprobación adicional.

**Confirmación:** dos pruebas sintéticas demuestran que la selección acepta
una firma inválida y una clave mal formada. Esto confirma la ausencia de
validación en esa capa; no demuestra que el transporte posterior acepte esa
clave, una conexión maliciosa exitosa ni un bypass de TLS. Es deuda previa
detectada al comparar el endurecimiento de Windows, no una vulnerabilidad
introducida por instalar Windows 5.1.8.

**Acción:** portar el contrato exacto de validación, fijar la clave pública
oficial y validar los bytes firmados sin normalizaciones incompatibles.
Descartar candidatos inválidos y comprobar de nuevo en el límite que abre
el túnel. Añadir pruebas de firma válida, firma ausente/manipulada, IP o label
alterados, claves mal formadas y catálogo en caché. No desactivar la
verificación TLS ni reinterpretar los fallos como pérdida de sesión.

### 2. Prioridad media: ciudades duplicadas reproducidas

Windows corrige el caso de una misma ciudad con servidores que incluyen
estado y otros que lo omiten en
[a384b649](https://github.com/ProtonVPN/win-app/commit/a384b6491907ca8310d272d286d7590764cefbfd).
Agrupa primero por país/ciudad; fusiona el estado ausente cuando hay un único
estado conocido, pero conserva estados distintos cuando hay ambigüedad real.

Nuestro `catalog.rs::insert_subdivision` separa siempre por estado, incluso
el vacío. `ProtonLocationsView.qml::buildSearchResults` agrega ambas listas.
**Confirmación:** con dos servidores sintéticos de Los Angeles, uno con
California y otro sin estado, `locations()` emite la ciudad dos veces.

**Acción:** normalizar la agrupación con la regla de upstream, preservar las
ciudades homónimas de estados distintos y comprobar Standard/P2P, búsqueda,
perfiles y selección efectiva de servidores. Evitar arreglar solamente el
texto o esconder una fila mientras la selección sigue siendo inconsistente.

### 3. Prioridad media: Smart Routing pierde el país físico

Windows añade país físico, etiquetas en listas y distintivo en la conexión,
incluyendo varios países físicos por grupo, en
[0dba863b](https://github.com/ProtonVPN/win-app/commit/0dba863b3e193953b413de690dccfa8246c34f5d).

Nuestro modelo deserializa `HostCountry`, pero `LogicalServer::serialized`
solo expone `smart_routing: bool`; no transmite el país físico. Tampoco hay
presentación de Smart Routing en los componentes actuales de la UI.
**Confirmación:** un servidor sintético de salida AR y host US pierde US al
serializarse para el frontend.

**Acción:** añadir campos de país físico al IPC de forma compatible y
mostrarlos en Países/servidores y Detalles de conexión, usando controles y
colores nativos de Omarchy. Distinguir país de salida, país físico y entrada
Secure Core; manejar correctamente `HostCountry` vacío.

### 4. Prioridad baja: el feedback no se oculta automáticamente

Windows añade un cierre automático configurable mediante el payload de
`IsConnectionFeedbackEnabled`, con 10 segundos como valor predeterminado,
en [96775c9d](https://github.com/ProtonVPN/win-app/commit/96775c9d3526a106e5fcaed8fb291736df1f5026).

Nuestro backend lee el flag como booleano y el frontend mantiene la pregunta
en Detalles mientras esté disponible y no se haya respondido. No transporta
ni aplica el intervalo. Es una diferencia de comportamiento, no una rotura de
conexión ni motivo para añadir telemetría sin consentimiento.

**Acción opcional:** propagar un intervalo validado y limitado; contar solo
mientras la pregunta sea visible, no enviar un voto por agotarse el tiempo y
mantener el opt-in de estadísticas. El resultado ignorado ya forma parte de
nuestro modelo de feedback.

## Cambios relevantes que no se deben copiar directamente

| Cambio de Windows | Evaluación para Omarchy |
| --- | --- |
| [Split tunneling Include, ab653e64](https://github.com/ProtonVPN/win-app/commit/ab653e6467a4687ba9cbced6d5269112f2f197a3) | Windows elimina rutas partidas `/1` que anulaban Include. Nuestro splitd usa marcas eBPF y reglas/tablas Linux con propiedad por UID. No hay un parche textual equivalente. Pendiente prueba de red aislada Include IPv4/IPv6, DNS y coexistencia con Kill Switch; esta revisión no demuestra ausencia de fugas. |
| [ProTun IPv6/Wintun, 613962d2](https://github.com/ProtonVPN/win-app/commit/613962d2884215aff821bff7a76ef3199876742c) | Nuestro constructor activa IPv6 solo si usuario y servidor lo permiten. No prueba que contenga todas las correcciones internas de ProTun. Verificar la dependencia Linux con servidores sin IPv6 antes de declarar equivalencia. LUID, NetBIOS y registro DDNS son específicos de Windows. |
| LLMNR y descubrimiento local | Nuestro acceso local DNS/multicast es opt-in y está desactivado por defecto, pero eso no equivale a haber deshabilitado LLMNR por interfaz en NetworkManager/resolved. Revisar en un namespace/laboratorio; no cambiar ajustes globales del escritorio por copiar Windows. |
| [ProTun v2, 31adf849](https://github.com/ProtonVPN/win-app/commit/31adf849c3b95d7d564951a790af7a592101818a), [actualización 61d068ad](https://github.com/ProtonVPN/win-app/commit/61d068adbb7a5d09753e30dce55469dad2b02e51) | Cambian FFI, cache, modos, label y solicitud de estadísticas de Windows. Nosotros usamos el servicio NM. El `protun.py` de Linux 5.6.10 instalado sigue construyendo JSON `version: 1` con `peers` compatible con el nuestro. No quitar nuestro Local Agent ni cambiar ese formato por el nombre de un commit de Windows. |
| [SNI aleatorio y estados ProTun](https://github.com/ProtonVPN/win-app/commit/613962d2884215aff821bff7a76ef3199876742c), [c6a02d80](https://github.com/ProtonVPN/win-app/commit/c6a02d80e3bcd58cdef122d1403cb189c32525d5) | Cambios de integración del motor, incluyendo no tratar cada error intermedio como desconexión definitiva. Revisar contra eventos reales del servicio Linux; la UI no debe imitar estados que NM no expone. |
| [Suspensión, eb6287db](https://github.com/ProtonVPN/win-app/commit/eb6287db96e4fa4723679cb5c76e53f0eb0ec256) | Ya evitamos conectar si antes estaba desconectado y Auto Connect está desactivado. La prueba booleana existente pasa. Mantener reconexión de un túnel que sí estaba activo; no confundirla con iniciar una VPN nueva. No se probó suspensión real en esta auditoría. |
| [Recientes, 6b36f1ec](https://github.com/ProtonVPN/win-app/commit/6b36f1ec0faf678c1391c3d7c236fb524fb7381d) | No usamos DateTime/JSON.NET ni registramos cada evento Connecting de Windows. `store.rs::record_recent` conserva pin, elimina duplicados y usa tiempos Unix en ms monótonos respecto al registro previo. No se encontró el mismo mecanismo del fallo. |
| [Carrera de auto-login, d6fd3d83](https://github.com/ProtonVPN/win-app/commit/d6fd3d8306e000ee6e0762a31742531a89c33b3f) | El arreglo Windows depende de Guest Hole. Nuestra carrera de restauración/auto-connect se corrigió en 0.9.7 y su prueba vuelve a pasar. Son mecanismos distintos. |
| [Guest Hole y firma, d742e9a8](https://github.com/ProtonVPN/win-app/commit/d742e9a81b48a90522df96e8d6c60ac6ac84ccf1), [relays, 10e878bb](https://github.com/ProtonVPN/win-app/commit/10e878bb9916a1064e6d86c8914b01c2edc0a56d) | Nuestro Alternative Routing usa DoH/hosts alternativos para la API; no implementa el túnel Guest Hole de Windows. No atribuirnos esa cobertura de anticensura por tener Alternative Routing. |
| [Certificado de cliente, 88ddeb12](https://github.com/ProtonVPN/win-app/commit/88ddeb12a057c40c23e77ed80ecae2284fe6f51f) | Windows centraliza parsing PEM. Nuestro bootstrap y refresh parsean X.509 y comprueban la clave pública esperada; no hay un cambio de formato de credenciales que portar. Conviene probar certificados persistidos mal formados en el límite de conexión, sin borrar la sesión. |
| [NAT-PMP, 343bac9d](https://github.com/ProtonVPN/win-app/commit/343bac9dbaf2fc579079acf922cfa3a52c49db2e) | Corrige tareas de recepción bloqueantes de .NET. Nuestro transporte es Tokio UDP asíncrono; no se copia esa gestión de threads/excepciones. |
| [Upsells solo Free, e3b06c69](https://github.com/ProtonVPN/win-app/commit/e3b06c69f934f4033a4ecc66575feb38d4895bbc) | No tenemos esos diálogos promocionales automáticos. Un aviso real de restricción P2P del servidor no debe suprimirse solo porque la cuenta sea de pago. |
| Tráfico, excepciones y UI de Windows | Los cambios revisados del scheduler son manejo de tareas y nombres de campos; no introducen un requisito nuevo para nuestro historial del gráfico. Tray, monitor, updater, COM/WinUI, redistribuibles VC++, NRPT, pipeline y tests de Windows no se portan. Traducciones nuevas se evalúan solo para nuestras cadenas ES/EN. |

## Pruebas y reproducción

Se añadió un parche de **cuatro pruebas de expectativa** a un worktree
desechable del core `7f1d2bf`; las cuatro fallan en 0.9.7 y confirman los
hallazgos 1–3. No son pruebas que deban añadirse al release como si pasaran.
No usan red, D-Bus, keyring ni credenciales reales.

Parche: [windows-upstream-2026-09-22-repro.patch](windows-upstream-2026-09-22-repro.patch).
En un checkout aislado de ese commit:

```bash
git apply /ruta/al/windows-upstream-2026-09-22-repro.patch
cargo test --locked --offline --package proton-omarchy-agent upstream_audit
```

Resultados: selección con firma inválida aceptada; selección con clave
mal formada aceptada; ciudad duplicada; país físico ausente del payload.
Para Smart Routing, `host_country_code` en la prueba es un nombre propuesto
para el contrato faltante, no un campo IPC ya acordado.

Se ejecutaron además, con resultado satisfactorio:

- `native_backend::lifecycle::tests::resume_restores_only_an_active_or_auto_connected_session`
- `autoconnect::tests::recovery_during_initial_account_request_still_auto_connects_once`

No se volvió a ejecutar toda la suite ni se probó tráfico real: no hubo
cambios de producción. El siguiente ciclo debe incorporar pruebas de red
aisladas para las áreas de motor/rutas antes de afirmar paridad completa.

## Orden propuesto

1. Validación firmada de endpoints y errores recuperables, conservando TLS y keyring.
2. Normalización de ciudades y campos/UI de Smart Routing.
3. Matriz Linux ProTun/Include/IPv6/DNS con dependencias actuales.
4. Cierre del feedback, si queremos adoptar ese comportamiento de producto.

Conservar las matrices de agosto como evidencia histórica. No subir su
commit de referencia a 5.1.8 ni mantener una afirmación de paridad completa
como si estos puntos ya estuvieran implementados y probados.

<h1 align="center">
  <br>
  <a href="https://nuclei.projectdiscovery.io"><img src="static/nuclei-logo.png" width="200px" alt="Nuclei"></a>
</h1>

<h4 align="center">Escáner de vulnerabilidades rápido y personalizable basado en un sencillo DSL basado en YAML.</h4>


<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/releases"><img src="https://img.shields.io/github/downloads/projectdiscovery/nuclei/total">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/releases/"><img src="https://img.shields.io/github/release/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/issues"><img src="https://img.shields.io/github/issues-raw/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/discussions"><img src="https://img.shields.io/github/discussions/projectdiscovery/nuclei">
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
<a href="https://twitter.com/pdnuclei"><img src="https://img.shields.io/twitter/follow/pdnuclei.svg?logo=twitter"></a>
</p>
      
<p align="center">
  <a href="#how-it-works">Cómo funciona</a> •
  <a href="#install-nuclei">Instalación</a> •
  <a href="https://docs.projectdiscovery.io/tools/nuclei/">Documentación</a> •
  <a href="#credits">Créditos</a> •
  <a href="https://docs.projectdiscovery.io/tools/nuclei/faq">Preguntas Frecuentes</a> •
  <a href="https://discord.gg/projectdiscovery">Únete a Discord</a>
</p>

<p align="center">
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README.md">English</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_CN.md">中文</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_KR.md">Korean</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ID.md">Indonesia</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ES.md">Spanish</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_PT-BR.md">Portuguese</a>
</p>

---

Nuclei se utiliza para enviar peticiones a múltiples objetivos basándose en una plantilla, lo que resulta en cero falsos positivos y proporciona un escaneo rápido en un gran número de hosts. Nuclei ofrece escaneos para una variedad de protocolos, incluyendo TCP, DNS, HTTP, SSL, File, Whois, Websocket, Headless, Code, etc. Con plantillas potentes y flexibles, Nuclei puede utilizarse para modelar todo tipo de comprobaciones de seguridad.

Tenemos un [repositorio dedicado](https://github.com/projectdiscovery/nuclei-templates) que alberga varios tipos de plantillas de vulnerabilidades, contribuidas por **más de 300** investigadores y ingenieros de seguridad.

## Cómo funciona


<h3 align="center">
  <img src="static/nuclei-flow.jpg" alt="nuclei-flow" width="700px"></a>
</h3>


| :exclamation:  **Descargo de responsabilidad**  |
|---------------------------------|
| **Este proyecto está en desarrollo activo**. Es de esperar que se produzcan cambios importantes con las nuevas versiones. Consulte el registro de cambios de la versión antes de actualizar. |
| Este proyecto fue principalmente desarrollado para ser utilizado como una herramienta CLI independiente. **Ejecutar nuclei como un servicio puede suponer riesgos de seguridad.** Se recomienda utilizarlo con precaución y tomar medidas de seguridad adicionales. |

# Instalación de Nuclei

Nuclei requiere **go1.22** para instalarse correctamente. Ejecute el siguiente comando para instalar la última versión -

```sh
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

<details>
  <summary>Brew</summary>
  
  ```sh
  brew install nuclei
  ```
  
</details>
<details>
  <summary>Docker</summary>
  
  ```sh
  docker pull projectdiscovery/nuclei:latest
  ```
  
</details>

**Más métodos de instalación [pueden encontrarse aquí](https://docs.projectdiscovery.io/tools/nuclei/install).**

<table>
<tr>
<td>  

### Plantillas de Nuclei

Nuclei cuenta con soporte incorporado para la descarga/actualización automática de plantillas desde la versión [v2.5.2](https://github.com/projectdiscovery/nuclei/releases/tag/v2.5.2) en adelante. El proyecto [**Nuclei-Templates**](https://github.com/projectdiscovery/nuclei-templates) proporciona una lista de plantillas listas para usar, aportadas por la comunidad, y que se actualizan constantemente.

También puedes utilizar la bandera `update-templates` para actualizar las plantillas de Nuclei en cualquier momento; puedes escribir tus propias pruebas para tu flujo de trabajo y necesidades individuales siguiendo la [guía de plantillas](https://docs.projectdiscovery.io/templates/) de Nuclei.

La sintaxis de referencia YAML DSL está disponible [aquí](SYNTAX-REFERENCE.md).

</td>
</tr>
</table>

### Uso

```sh
nuclei -h
```

Esto mostrará ayuda sobre la herramienta. Aquí están todas las opciones que soporta.


```console
Nuclei es un escáner de vulnerabilidades rápido y basado en plantillas
que se centra en su amplia configurabilidad, extensibilidad y facilidad de uso.

Usage:
  ./nuclei [flags]

Flags:
TARGET:
   -u, -target string[]          URLs/hosts a escanear
   -l, -list string              ruta al archivo que contiene la lista de URLs/hosts a escanear (uno por línea)
   -eh, -exclude-hosts string[]  hosts a excluir para escanear de la lista de entrada (ip, cidr, hostname)
   -resume string                reanudar el escaneo usando resume.cfg (la clusterización quedará inhabilitada)
   -sa, -scan-all-ips            escanear todas las IP asociadas al registro dns
   -iv, -ip-version string[]     versión IP a escanear del nombre de host (4,6) - (por defecto 4)

TARGET-FORMAT:
   -im, -input-mode string        modo del archivo de entrada (list, burp, jsonl, yaml, openapi, swagger) (por defecto "list")
   -ro, -required-only            utilizar solo campos requeridos en el formato de entrada al generar peticiones
   -sfv, -skip-format-validation  saltar la validación de formato (como variables faltantes) al procesar el archivo de entrada

TEMPLATES:
   -nt, -new-templates                    ejecutar sólo las nuevas plantillas añadidas en la última versión de nuclei-templates
   -ntv, -new-templates-version string[]  ejecutar las nuevas plantillas añadidas en la versión especificada
   -as, -automatic-scan                   escaneo web automático utilizando la detección de tecnología de wappalyzer para mapeo de etiquetas
   -t, -templates string[]                lista de plantillas o directorio de plantillas a ejecutar (separadas por comas, file)
   -turl, -template-url string[]          url de plantilla o lista que contiene urls de plantillas a ejecutar (separadas por comas, file)
   -w, -workflows string[]                lista de flujos de trabajo o directorio de flujos de trabajo a ejecutar (separadas por comas, file)
   -wurl, -workflow-url string[]          url de flujo de trabajo o lista que contiene urls de flujo de trabajo para ejecutar (separadas por comas, file)
   -validate                              valida las plantillas pasadas a nuclei
   -nss, -no-strict-syntax                deshabilita la comprobación de sintaxis estricta en las plantillas
   -td, -template-display                 muestra el contenido de las plantillas
   -tl                                    lista todas las plantillas disponibles
   -tgl                                   lista todas las etiquetas disponibles
   -sign                                  firma las plantillas con la clave privada definida en la variable de entorno NUCLEI_SIGNATURE_PRIVATE_KEY
   -code                                  habilita la carga de plantillas basadas en protocolos de código
   -dut, -disable-unsigned-templates      deshabilita la ejecución de plantillas no firmadas o plantillas con firma no coincidente

FILTERING:
   -a, -author string[]               plantillas a ejecutar basadas en autores (separadas por comas, file)
   -tags string[]                     plantillas a ejecutar basadas en etiquetas (separadas por comas, file)
   -etags, -exclude-tags string[]     plantillas a excluir basadas en etiquetas (separadas por comas, file)
   -itags, -include-tags string[]     etiquetas a ejecutar incluso si están excluidas ya sea por defecto o por configuración
   -id, -template-id string[]         plantillas a ejecutar basadas en IDs de plantilla (comma-separated, file, allow-wildcard)
   -eid, -exclude-id string[]         plantillas a excluir basadas en IDs de plantilla (separadas por comas, file)
   -it, -include-templates string[]   ruta al archivo de plantilla o directorio a ejecutar incluso si están excluidas ya sea por defecto o por configuración
   -et, -exclude-templates string[]   ruta al archivo de plantilla o directorio a excluir (separadas por comas, file)
   -em, -exclude-matchers string[]    matchers de plantilla a excluir en el resultado
   -s, -severity value[]              plantillas a ejecutar basadas en criticidad. Valores posibles: info, bajo, medio, alto, crítico, desconocido
   -es, -exclude-severity value[]     plantillas a excluir basadas en criticidad. Valores posibles: info, bajo, medio, alto, crítico, desconocido
   -pt, -type value[]                 plantillas a ejecutar basadas en tipo de protocolo. Valores posibles: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -ept, -exclude-type value[]        plantillas a excluir basadas en tipo de protocolo. Valores posibles: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -tc, -template-condition string[]  plantillas a ejecutar basadas en condición de expresión

OUTPUT:
   -o, -output string            archivo de salida donde guardar las incidencias/vulnerabilidades detectadas
   -sresp, -store-resp           almacenar todas las peticiones/respuestas enviadas por nuclei en el directorio de salida
   -srd, -store-resp-dir string  almacenar todas las peticiones/respuestas enviadas por nuclei en un directorio personalizado (por defecto "output")
   -silent                       mostrar resultados únicamente
   -nc, -no-color                deshabilitar la coloración del contenido de salida (códigos de escape ANSI)
   -j, -jsonl                    escribir la salida en formato JSONL(ines)
   -irr, -include-rr -omit-raw   incluir pares peticiones/respuesta en las salidas JSON, JSONL y Markdown (sólo para hallazgos) [OBSOLETO usar -omit-raw] (por defecto true)
   -or, -omit-raw                omitir los pares peticiones/respuesta en las salidas JSON, JSONL y Markdown (sólo para hallazgos)
   -ot, -omit-template           omitir plantilla codificada en la salida JSON, JSONL
   -nm, -no-meta                 deshabilitar la impresión de metadatos de resultados en la salida cli
   -ts, -timestamp               habilitar la impresión de la marca de tiempo en la salida cli
   -rdb, -report-db string       base de datos de informes de nuclei (utilizarla siempre para persistir los datos de los informes)
   -ms, -matcher-status          mostrar el estado de fallo de coincidencia
   -me, -markdown-export string  directorio para exportar resultados en formato markdown
   -se, -sarif-export string     archivo para exportar resultados en formato SARIF
   -je, -json-export string      archivo para exportar resultados en formato JSON
   -jle, -jsonl-export string    archivo para exportar resultados en formato JSONL(ines)

CONFIGURATIONS:
   -config string                        ruta al archivo de configuración de nuclei
   -fr, -follow-redirects                habilitar el seguimiento de redirecciones para plantillas http
   -fhr, -follow-host-redirects          seguir redirecciones en el mismo host
   -mr, -max-redirects int               número máximo de redirecciones a seguir para plantillas http (por defecto 10)
   -dr, -disable-redirects               deshabilitar redirecciones para plantillas http
   -rc, -report-config string            archivo de configuración del módulo de informes de nuclei
   -H, -header string[]                  encabezado/cookie personalizado a incluir en todas las peticiones http en formato header:value (cli, file)
   -V, -var value                        variables personalizadas en formato key=value
   -r, -resolvers string                 archivo que contiene lista de resolutores para nuclei
   -sr, -system-resolvers                utilizar resolución de DNS del sistema como fallback de error
   -dc, -disable-clustering              deshabilitar la clusterización de peticiones
   -passive                              habilitar el modo de procesamiento pasivo de respuestas HTTP
   -fh2, -force-http2                    forzar la conexión http2 en las peticiones
   -ev, -env-vars                        habilitar el uso de variables de entorno en la plantilla
   -cc, -client-cert string              archivo de certificado de cliente (codificado en PEM) utilizado para autenticarse contra los hosts escaneados
   -ck, -client-key string               archivo de clave de cliente (codificado en PEM) utilizado para autenticarse contra los hosts escaneados
   -ca, -client-ca string                archivo de autoridad de certificación de cliente (codificado en PEM) utilizado para autenticarse contra los hosts escaneados
   -sml, -show-match-line                mostrar líneas de coincidencia para plantillas de archivo, funciona solo con extractores
   -ztls                                 utilizar la biblioteca ztls con autofallback a estándar para tls13 [Obsoleto] autofallback a ztls está habilitado por defecto
   -sni string                           nombre de host tls sni a usar (por defecto: nombre de dominio de entrada)
   -dt, -dialer-timeout value            tiempo de espera para peticiones de red
   -dka, -dialer-keep-alive value        duración de keep-alive para peticiones de red
   -lfa, -allow-local-file-access        permite el acceso a archivos (carga útil) en cualquier lugar del sistema
   -lna, -restrict-local-network-access  bloquea conexiones a la red local / privada
   -i, -interface string                 interfaz de red a usar para el escaneo de red
   -at, -attack-type string              tipo de combinaciones de carga útil a realizar (batteringram, pitchfork, clusterbomb)
   -sip, -source-ip string               dirección ip de origen a usar para el escaneo de red
   -rsr, -response-size-read int         tamaño máximo de respuesta a leer en bytes (por defecto 10485760)
   -rss, -response-size-save int         tamaño máximo de respuesta a guardar en bytes (por defecto 1048576)
   -reset                                reset elimina todos los archivos de configuración y datos de nuclei (incluidas las nuclei-templates)
   -tlsi, -tls-impersonate               habilitar client hello (ja3) tls randomization experimental

INTERACTSH:
   -iserver, -interactsh-server string  url del servidor interactsh para instancia autoalojada (por defecto: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)
   -itoken, -interactsh-token string    token de autenticación del servidor interactsh autoalojado
   -interactions-cache-size int         número de peticiones a mantener en la caché de interacciones (por defecto 5000)
   -interactions-eviction int           número de segundos a esperar antes de eliminar las solicitudes de la caché (por defecto 60)
   -interactions-poll-duration int      número de segundos a esperar antes de cada solicitud de polling de interacciones (por defecto 5)
   -interactions-cooldown-period int    tiempo adicional para el polling de interacciones antes de salir (por defecto 5)
   -ni, -no-interactsh                  desactivar el servidor interactsh para pruebas OAST, excluir plantillas basadas en OAST

FUZZING:
   -ft, -fuzzing-type string  sobrescribe el tipo de fuzzing establecido en la plantilla (replace, prefix, postfix, infix)
   -fm, -fuzzing-mode string  sobrescribe el modo de fuzzing establecido en la plantilla (multiple, single)
   -fuzz                      habilita la carga de plantillas de fuzzing (Obsoleto: usar -dast en su lugar)
   -dast                      solo ejecuta plantillas DAST

UNCOVER:
   -uc, -uncover                  habilita el motor uncover
   -uq, -uncover-query string[]   consulta de búsqueda uncover
   -ue, -uncover-engine string[]  motor de búsqueda uncover (shodan,censys,fofa,shodan-idb,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow) (por defecto shodan)
   -uf, -uncover-field string     campos uncover a devolver (ip,port,host) (por defecto "ip:port")
   -ul, -uncover-limit int        resultados uncover a devolver (por defecto 100)
   -ur, -uncover-ratelimit int    sobrescribe el límite de velocidad de los motores con el límite de velocidad del motor uncover (por defecto 60 req/min) (por defecto 60)

RATE-LIMIT:
   -rl, -rate-limit int               número máximo de peticiones a enviar por segundo (por defecto 150)
   -rlm, -rate-limit-minute int       número máximo de peticiones a enviar por minuto
   -bs, -bulk-size int                número máximo de hosts a ser analizados en paralelo por plantilla (por defecto 25)
   -c, -concurrency int               número máximo de plantillas a ejecutar en paralelo (por defecto 25)
   -hbs, -headless-bulk-size int      número máximo de hosts headless a ser analizados en paralelo por plantilla (por defecto 10)
   -headc, -headless-concurrency int  número máximo de plantillas headless a ejecutar en paralelo (por defecto 10)
   -jsc, -js-concurrency int          número máximo de entornos de ejecución de JavaScript a ejecutar en paralelo (por defecto 120)
   -pc, -payload-concurrency int      concurrencia máxima de carga útil para cada plantilla (por defecto 25)

OPTIMIZATIONS:
   -timeout int                     tiempo de espera en segundos (por defecto 10)
   -retries int                     número de veces que se reintenta una petición fallida (por defecto 1)
   -ldp, -leave-default-ports       dejar puertos HTTP/HTTPS predeterminados (por ejemplo, host:80,host:443)
   -mhe, -max-host-error int        errores máximos para un host antes de omitirlo del escaneo (por defecto 30)
   -te, -track-error string[]       agrega el error dado a la lista de seguimiento de errores máximos por host (standard, file)
   -nmhe, -no-mhe                   deshabilita la omisión del host del escaneo basado en errores
   -project                         utiliza una carpeta de proyecto para evitar enviar la misma petición varias veces
   -project-path string             establece una ruta de proyecto específica (por defecto "/tmp")
   -spm, -stop-at-first-match       detiene el procesamiento de las peticiones HTTP después de la primera coincidencia (puede romper la lógica de la plantilla/flujo de trabajo)
   -stream                          modo transmisión - comienza a trabajar sin ordenar la entrada
   -ss, -scan-strategy value        estrategia a utilizar mientras se escanea (auto/host-spray/template-spray) (por defecto auto)
   -irt, -input-read-timeout value  tiempo de espera en la lectura de entrada (por defecto 3m0s)
   -nh, -no-httpx                   deshabilita análisis httpx para entradas que no son URL
   -no-stdin                        deshabilita el procesamiento de la entrada estándar

HEADLESS:
   -headless                        habilita las plantillas que requieren soporte de navegadores sin interfaz gráfica (headless browser) (el usuario root en Linux deshabilitará el sandbox)
   -page-timeout int                segundos para esperar cada página en modo sin interfaz (por defecto 20)
   -sb, -show-browser               muestra el navegador en la pantalla al ejecutar plantillas con modo sin interfaz
   -ho, -headless-options string[]  inicia Chrome en modo sin interfaz con opciones adicionales
   -sc, -system-chrome              utiliza el navegador Chrome instalado localmente en lugar del instalado por nuclei
   -lha, -list-headless-action      lista de acciones sin interfaz disponibles

DEBUG:
   -debug                    muestra todas las peticiones y respuestas
   -dreq, -debug-req         muestra todas las peticiones enviadas
   -dresp, -debug-resp       muestra todas las respuestas recibidas
   -p, -proxy string[]       lista de proxies http/socks5 a utilizar (separados por comas o archivo de entrada)
   -pi, -proxy-internal      proxy para todas las peticiones internas
   -ldf, -list-dsl-function  lista todas las firmas de función DSL admitidas
   -tlog, -trace-log string  archivo a escribir el registro de traza de peticiones enviadas
   -elog, -error-log string  archivo a escribir el registro de error de peticiones enviadas
   -version                  muestra la versión de nuclei
   -hm, -hang-monitor        habilita la monitorización de bloqueos de nuclei
   -v, -verbose              muestra salida detallada
   -profile-mem string       archivo opcional de volcado de memoria de nuclei
   -vv                       muestra las plantillas cargadas para el escaneo
   -svd, -show-var-dump      muestra el volcado de variables para depuración
   -ep, -enable-pprof        habilita el servidor de depuración pprof
   -tv, -templates-version   muestra la versión de las plantillas nuclei (nuclei-templates) instaladas
   -hc, -health-check        ejecuta comprobación de diagnóstico

UPDATE:
   -up, -update                      actualiza el motor de nuclei a la última versión lanzada
   -ut, -update-templates            actualiza nuclei-templates a la última versión lanzada
   -ud, -update-template-dir string  directorio personalizado para instalar/actualizar nuclei-templates
   -duc, -disable-update-check       deshabilita la comprobación automática de actualizaciones de nuclei/templates

STATISTICS:
   -stats                    muestra estadísticas sobre el escaneo en ejecución
   -sj, -stats-json          muestra estadísticas en formato JSONL(ines)
   -si, -stats-interval int  número de segundos a esperar entre mostrar una actualización de estadísticas (por defecto 5)
   -mp, -metrics-port int    puerto para exponer métricas de nuclei (por defecto 9092)

CLOUD:
   -auth                  configura la clave de API del cloud de projectdiscovery (pdcp)
   -cup, -cloud-upload    sube los resultados del escaneo al dashboard de pdcp
   -sid, -scan-id string  sube los resultados del escaneo al ID de escaneo dado

AUTHENTICATION:
   -sf, -secret-file string[]  ruta al archivo de configuración que contiene los secrets para el escaneo autenticado de nuclei
   -ps, -prefetch-secrets      precarga los secrets del archivo de secrets


EXAMPLES:
Ejecutar nuclei en un solo host:
   $ nuclei -target example.com

Ejecutar nuclei con directorios de plantillas específicos:
   $ nuclei -target example.com -t http/cves/ -t ssl

Ejecutar nuclei contra una lista de hosts:
   $ nuclei -list hosts.txt

Ejecutar nuclei con una salida JSON:
   $ nuclei -target example.com -json-export output.json

Ejecutar nuclei con salidas Markdown ordenadas (con variables de entorno):
   $ MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclei_report/

Documentación adicional disponible en: https://docs.nuclei.sh/getting-started/running
```

### Ejecutando Nuclei

Consulta https://docs.projectdiscovery.io/tools/nuclei/running para obtener detalles sobre cómo ejecutar Nuclei.

### Uso de Nuclei desde código Go

La guía completa sobre cómo usar Nuclei como biblioteca/SDK está disponible en [godoc](https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/lib#section-readme).


### Recursos

Puedes acceder a la documentación principal de Nuclei en https://docs.projectdiscovery.io/tools/nuclei/, y obtener más información sobre Nuclei en la nube con [ProjectDiscovery Cloud Platform](https://cloud.projectdiscovery.io).

¡Consulta https://docs.projectdiscovery.io/tools/nuclei/resources para obtener más recursos y videos sobre Nuclei!

### Créditos

Gracias a todos los increíbles [contribuyentes de la comunidad que enviaron PRs](https://github.com/projectdiscovery/nuclei/graphs/contributors) y mantienen este proyecto actualizado. :heart:

Si tienes una idea o algún tipo de mejora, eres bienvenido a contribuir y participar en el Proyecto, siéntete libre de enviar tu PR.

<p align="center">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=projectdiscovery/nuclei&max=500">
</a>
</p>


También echa un vistazo a los siguientes proyectos de código abierto similares que pueden adaptarse a tu flujo de trabajo:

[FFuF](https://github.com/ffuf/ffuf), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [Jaeles](https://github.com/jaeles-project/jaeles), [ChopChop](https://github.com/michelin/ChopChop)

### Licencia

Nuclei se distribuye bajo la [Licencia MIT](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md)

<h1 align="left">
  <a href="https://discord.gg/projectdiscovery"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a> <a href="https://docs.projectdiscovery.io"><img src="static/check-nuclei-documentation.png" width="380" alt="Check Nuclei Documentation"></a>
</h1>

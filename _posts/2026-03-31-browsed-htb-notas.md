---
title: "Browsed - HTB - Notas de Estudio"
date: 2026-03-31T22:00:00-04:00
categories:

* cajas
tags:
* htb
* chrome-extensions
* command-injection
* pyc
* web
---

# Browsed HTB - Notas de Estudio

## Chrome Extensions y Manifest V3

### Por que importa la version de Chrome y el Manifest?

La version de Chrome no hace la maquina mas vulnerable, solo importa para compatibilidad. Chrome v134 usa MV3, entonces la extension debe estar construida para MV3 o no carga. MV3 es el manifest version actual, no existe MV4. MV2 fue deprecado en 2022.

### Cual es la diferencia entre permissions y host_permissions?

En MV2 todo estaba junto en `permissions`. MV3 los separo. `permissions` define que APIs puede usar la extension (tabs, storage, webRequest, etc.) y `host_permissions` define en que sitios puede operar. La separacion es para hacer mas explicito que puede hacer la extension versus donde puede hacerlo.

### Por que se usa background y no action o commands?

`action` requiere que el usuario haga click. `commands` requiere que presione una tecla. `background` corre automaticamente al instalar la extension, invisible, sin interaccion del usuario. Para un ataque silencioso la unica opcion viable es `background`.

### No hace esto peligrosas a todas las extensiones con background?

No inherentemente. El `background` script solo es peligroso combinado con permisos amplios como `webRequest` y `host_permissions: <all_urls>`. Chrome muestra explicitamente los permisos al instalar y las extensiones del Web Store son revisadas. El problema real en esta maquina es que el developer instala ciegamente cualquier extension subida, es el mismo riesgo que abrir attachments de email random.

### Que APIs exclusivas tienen las extensiones que un sitio web normal no tiene?

Las extensiones tienen acceso al namespace `chrome.*`. Las mas interesantes desde perspectiva de seguridad son `chrome.webRequest` para interceptar requests, `chrome.scripting` para inyectar JS en paginas, `chrome.cookies` para robar sesiones, `chrome.tabs.captureVisibleTab` para screenshots silenciosos, y `chrome.history` para ver el historial completo.

### Por que esta maquina solo uso webRequest y no algo mas peligroso?

El servidor corre Chrome por solo 10 segundos en una sesion automatizada sin usuario real, sin historial, sin cookies, sin sesiones activas. Lo unico util era capturar que URLs visita ese Chrome automatizado. En un escenario donde un humano usa su browser del dia a dia, las APIs mas peligrosas serian devastadoras.

---

## El servidor procesando las extensiones

### Que revela el comando que ejecuta el servidor?

Al procesar la extension subida, el servidor corre Chrome con `--no-sandbox`, `--load-extension` apuntando al zip extraido, y visita `browsedinternals.htb` automaticamente. Esto le entrega el hostname interno al atacante sin que tenga que adivinarlo.

### El --no-sandbox fue critico para el exploit?

No. El exploit no requeria escapar del browser. La extension solo hacia HTTP requests, que Chrome permite con o sin sandbox. El codigo malicioso se ejecuto server-side via bash injection en Flask. El `--no-sandbox` es consecuencia de correr Chrome headless en Linux donde el sandbox a veces causa problemas de compatibilidad, no una vulnerabilidad intencional.

### Chrome en Windows corre con sandbox?

Si, por defecto. El sandbox protege contra sitios web maliciosos aislando el renderer process del OS. Las extensiones estan en una capa superior con mas privilegios y el sandbox no las restringe de la misma manera. Por eso instalar una extension maliciosa es mucho mas peligroso que visitar un sitio malicioso.

---

## Primera extension -- Spy

### Por que no alcanza con python -m http.server para recibir los datos?

`python -m http.server` solo sirve archivos y no lee request bodies. La extension envia POST requests con JSON en el body. Se necesita un servidor que lea y muestre ese body. `nc -lvnkp 4444` con el flag `-k` mantiene netcat escuchando indefinidamente pero muestra raw HTTP sin formatear, dificil de parsear.

### Por que no usar webhook.site o requestbin?

Son servicios gratuitos que dan una URL temporal que loguea cualquier request recibido, utiles cuando el target tiene acceso a internet. En HTB no funcionan porque la maquina esta aislada en la red privada del lab y no puede alcanzar internet.

### Por que onBeforeRequest y no chrome.tabs.onUpdated?

`onBeforeRequest` captura todo, incluyendo imagenes, fonts y API calls background. `tabs.onUpdated` solo captura navegaciones completas y habria perdido muchos hostnames internos que aparecen en requests de recursos.

---

## Segunda extension -- Reverse Shell

### Es importante el nombre de la funcion onExtensionLoaded?

Completamente arbitrario. Podria llamarse de cualquier manera o ni siquiera ser una funcion, el fetch puede ir directo en top-level. El codigo top-level en un service worker se ejecuta inmediatamente al cargar sin necesitar event handlers.

### Por que el payload va en base64?

El payload contiene `/` en `/dev/tcp/IP/PORT` y Flask interpreta los slashes como separadores de path en el routing, causando un 404. Base64 elimina ese problema porque solo usa caracteres alfanumericos y algunos simbolos que no interfieren con el routing.

### Como puede la extension llegar a 127.0.0.1 si esta en el browser?

La extension corre dentro del browser del developer, que esta en la maquina target. Desde el browser, localhost es la maquina target misma, dando acceso al Flask app que esta bloqueado desde afuera por firewall.

---

## Bash -eq Arithmetic Injection

### Por que es vulnerable si el input esta quoted?

El developer hizo dos cosas correctas: uso `subprocess.run` sin `shell=True` en Python y el argumento esta quoted con `"$1"` en bash. El problema es que las quotes no protegen contra arithmetic evaluation. `-eq` fuerza a bash a evaluar ambos lados como expresiones aritmeticas y bash soporta `$()` command substitution dentro de aritmetica, entonces ejecuta cualquier cosa dentro de `$()` al resolver la expresion.

### Por que x[ y no otro formato?

La letra es completamente arbitraria, podria ser cualquier nombre de variable valido. Lo que importa son los corchetes. Bash interpreta `variable[...]` como array index syntax, lo que fuerza evaluacion aritmetica del contenido. Sin los corchetes bash no tomaria el mismo path de evaluacion.

### Cual es la diferencia entre subprocess con y sin shell=True?

Sin `shell=True` Python ejecuta el programa directamente, pasando los argumentos como literales. Caracteres como `;`, `|`, `$()` no tienen significado especial. Con `shell=True` Python pasa el string completo a `/bin/sh` para que lo interprete, haciendo posible la inyeccion directamente desde Python. La leccion es que puedes hacer todo bien en Python y aun asi ser vulnerable si el script que llamas tiene sus propias vulnerabilidades de parsing.

---

## Privilege Escalation -- .pyc Hijack

### Por que larry no puede crear __pycache__ el mismo?

El directorio padre `/opt/extensiontool/` es owned by root con permisos `755`. Larry puede leer y ejecutar pero no escribir. Python crea `__pycache__` al importar un modulo pero si no tiene permisos de escritura en el directorio padre simplemente falla sin crear nada.

### El cron job es solo conveniencia de CTF?

No, es parte necesaria de la cadena de vulnerabilidad. Root corrio el script primero durante el setup, entonces `__pycache__` se creo owned by root. Sin el cron reseteando a `777` larry no puede escribir dentro aunque tenga acceso sudo al script. Ademas implica un tiempo limite de aproximadamente 5 minutos entre que el cron resetea y que debes ejecutar el exploit.

### Por que Python carga el .pyc en lugar del .py?

Python busca primero el `.pyc` en `__pycache__`. Si lo encuentra, lo carga directamente sin mirar el `.py`. Es una optimizacion de performance para evitar recompilar en cada import.

### Por que py_compile crea una carpeta __pycache__ en lugar del .pyc directo?

Eso cambio entre Python 2 y Python 3. Python 2 creaba el `.pyc` junto al `.py` en la misma carpeta. Python 3 introdujo `__pycache__` para mantener directorios mas limpios y para soportar multiples versiones de Python coexistiendo, ya que el nombre del archivo incluye la version como `modulo.cpython-312.pyc`.

### El nombre __pycache__ implica que se borra automaticamente?

No. Es cache en el sentido de resultado precomputado, no temporal. Python lo invalida solo cuando detecta cambios en el source comparando timestamp y size. No se borra automaticamente a menos que algo externo lo haga, como el cron job en esta maquina.

### Como esta estructurado el header de 16 bytes de un .pyc?

Los primeros 4 bytes son el magic number que identifica la version de Python. Los siguientes 4 son los flags de validacion. Los siguientes 4 son el timestamp del source `.py` en Unix epoch little-endian. Los ultimos 4 son el size del source `.py`. El bytecode empieza en el byte 17.

### Por que no funciono cambiar los flags a 02 para saltarse la validacion?

Se intento poner flag `02` (unchecked hash, confiar ciegamente) editando el binario con vim y xxd. Editar binarios con editores de texto es propenso a corrupcion. Incluso haciendolo correctamente con Python en modo `r+b`, puede fallar por incompatibilidades en el bytecode entre subversiones de Python 3.12. El header transplant es mas confiable porque copia exactamente los 16 bytes correctos en un solo paso.

### En que consiste el header transplant?

Python valida el header comparandolo contra el source `.py`. Si el `.pyc` malicioso tiene un header que referencia `evil_module.py`, el timestamp y size no coinciden con `extension_utils.py` y Python recompila desde la fuente legitima. La solucion es copiar los primeros 16 bytes del `.pyc` legitimo al malicioso. Python verifica el header, todo coincide, y carga el bytecode malicioso sin cuestionar nada.

### El bytecode .pyc es seguro para proteger codigo?

No. Puede ser decompilado casi perfectamente con herramientas como `uncompyle6`. Para proteccion real existen opciones como Cython que compila Python a C nativo, Nuitka que produce un binario standalone, o PyArmor que encripta el bytecode con una capa de runtime. Ninguna es perfectamente inviolable si el codigo corre en la maquina del usuario.

---

## Magic Numbers

### Los magic numbers son especificos de Python?

No, son un concepto universal. Todo tipo de archivo tiene una secuencia de bytes al inicio que lo identifica independientemente de su extension. ELF binaries en Linux empiezan con `7F 45 4C 46`, archivos ZIP con `50 4B 03 04`, PDFs con `25 50 44 46`. El comando `file` en Linux usa magic numbers para identificar el tipo real de un archivo sin importar su extension, util en CTFs cuando encuentras archivos de tipo desconocido.

### El magic number 0D0D0D0A es especifico de Python 3.12 o puede ser otra cosa?

Es especifico de Python 3.12. No hay un registro global que reserve secuencias de bytes entre todos los formatos, pero en la practica ese patron especifico es reconocido como Python 3.12. Los ultimos dos bytes `0D 0A` son siempre iguales en todas las versiones de Python, un artifact historico intencional para detectar corrupcion si el archivo se procesa como texto en lugar de binario.

---

Tambien dejo mi usuario para dar respetos en HTB si encontraron esto util:

https://app.hackthebox.com/users/337909

Gracias y saludos!
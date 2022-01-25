---
title: "Borderlands - THM Writeup"
date: 2022-01-24T18:34:00-04:00
categories:
  - cajas
tags:
  - thm
  - pivoting
  - network
  - brute
---
![image](https://tryhackme-images.s3.amazonaws.com/room-icons/5e7d20ffad76e15bdd1738fa32d86fd9.png){: width="100"}

Aca presentamos una guia de la maquina `Borderlands` en [TryHackMe](https://tryhackme.com/room/borderlands) en la cual en el mismo enunciado se indica que se debe hacer [pivoting](https://csrc.nist.gov/glossary/term/pivot#:~:text=Definition(s)%3A,allow%20an%20attacker%20to%20pivot.) a traves de una red con un diagrama interesante.

This challenge was created by Context Information Security for TryHackMe HackBack2, a cyber security consultancy that employs some of the best in the industry. Deploy the network and answer the questions below. Some questions will show [X] next to them. This means the question is worth X extra points.
{: .alert .alert-info}
![image](https://i.imgur.com/dKUeS0q.png){: width="100"}

Una vez logeados, procedemos a iniciar la maquina ~~y agregarle 1 hora mas por si acaso~~, luego nos conectamos al VPN con
> `sudo openvpn /PATHTO/USER.ovpn`{:.language-bash .highlight}

Con esto empezamos...

## RECONOCIMIENTO

Primeramente podemos realizar un reconocimiento del tipo del sistema operativo usado en la maquina cliente con
> `ping -c 1 10.10.98.122`{:.language-bash .highlight}
![image](https://user-images.githubusercontent.com/85322110/150825664-ed91867a-60af-4ae8-8e2d-61da1b922617.png)

Y con esto en base al TTL obtenido en la respuesta podemos asumir que si se acerca a 64, el sistema es Linux, y si se acerca a 128, es un sistema Windows, en este caso apreciamos que es de `63` asi que asumimos un sistema `Linux`.

Luego podemos escanear los puertos abiertos en la maquina victima con la herramienta `nmap` usando las siguientes opciones
> `nmap -sS --min-rate=600 --open -v -n -Pn 10.10.98.122 -oN puertos.txt`{:.language-bash .highlight}
![image](https://user-images.githubusercontent.com/85322110/150827380-bb6b6a33-7105-47c0-9564-8a9c4ba452dc.png)

Con esto usamos un `TCP SYN ACK Scan` con `-sS` para no esperar por respuesta del servidor luego de detectar que el puerto esta efectivamente abierto, usamos un `--min-rate` de 600 para usar un minimo de 600 paquetes por periodo, luego listamos los puertos de estado `--open`, usamos el `-v`erbose para ver los puertos en pantalla, quitamos la resolucion DNS con `-n` y desactivamos el `Host Discovery` con `-Pn`, finalmente exportamos la salida a un archivo `-oN puertos.txt` para futura referencia.

Aca vemos dos puertos abiertos `22,80` con los cual vamos a seguir usando `nmap` pasandole `-sC` scripts basicos de enumeracion asi como detectar la version de los servicios con `-sV` y exportar la salida con `-oN`
> `nmap -sC -sV -p22,80 10.10.98.122 -oN version.txt`
![image](https://user-images.githubusercontent.com/85322110/150828146-2d3e82c3-3986-4c1c-a872-cf3fa216b5b0.png)

Vemos un directorio interestante `/.git` que analizaremos mas adelante, de resto continuamos con la siguiente fase...

## ESCANEO

De por si ya sabemos que con el puerto `SSH 22` no podremos hacer nada sin credenciales por los momentos, asi que vamos a proceder a escanear la pagina `HTTP 80`. Abrimos el navegador y nos vamos a la pagina `http://10.10.98.122/`, vemos por alli un archivo para descargar `.apk` que es Aplicacion de Android, y unos Archivos PDFs subidos en la pagina, ademas de un campo para logearnos en la pagina pero las credenciales por defecto parecen no funcionar.

Nos podemos descargar uno de los archivos `.pdf`, y con usar `exiftool` vemos un potencial usuario llamado `billg` en el campo `Author:`
![image](https://user-images.githubusercontent.com/85322110/150828848-a324fea5-2a30-4230-8735-975f2c7bdc90.png)

Con esto podemos hacer uso de la herramienta `wfuzz` para intentar hacer un ataque de fuerza bruta a ese login sabiendo que debemos enviar una peticion `POST` con el payload `username=billg&password=FUZZ`, para antes poder tener nuestro diccionario, haremos una copia de las primeras 10000 lineas del archivo `rockyou.txt` para no sobrecargar al wfuzz con `head -n 10000 /usr/share/wordlists/rockyou.txt > dict.txt` y ocultamos la respuesta con `40Ch` cuando la clave es incorrecta:
> `wfuzz -c --hh=40 -w dict.txt -d "username=billg&password=FUZZ" http://10.10.98.122`{:.language-bash .highlight}

Mientras esto corre de fondo, vamos a proceder a chequear ese directorio `/.git` que vimos anteriormente, al intentar acceder, recibimos un error `403`, pero si intentamos descargarnos el archivo en `http://10.10.98.122/.git/logs/HEAD` efectivamente logramos la descarga, esto es potencialmente peligroso pues con la informacion contenida en ese archivo podremos acceder a datos pasados del historial del proyecto `git`. Procedemos a crearnos una nueva carpeta, nos metemos en ella, y hacemos `git init`{:.language-bash .highlight} para crear un proyecto git vacio, y luego nos copiamos el archivo `HEAD` aca para usarlo como referencia.

Si vemos este archivo observamos una serie de `commit`s que se ejecutaron en este proyecto, y llama la atencion uno donde indica `removed sensitive data`, asi que con esto procedemos a copiar el numero identificador del commit anterior, o de la primera columna, ya que la segunda columna representa el commit actual


Ahora vamos a descargar el archivo `.apk` y primeramente vamos a extraer la informacion de este haciendo uso de `apktool d`:
![image](https://user-images.githubusercontent.com/85322110/150831486-71b6e404-65ac-4ec3-9280-cb96e4bb4d14.png)

Con ello vemos una serie de carpetas y archivos, en este caso nos interesa ver los valores asignados a variables, estos se encuentran en `res/values/` en el archivo `strings.xml`, aca encontramos una `encrypted_api_key`
![image](https://user-images.githubusercontent.com/85322110/150848881-14f59d99-d550-43a1-8fce-1739ef405d1d.png)


![image](https://user-images.githubusercontent.com/85322110/150830716-c1d5831a-a65d-488c-a5b1-f925e338430b.png)

## ESCALADA DE PRIVILEGIOS



Saludos!

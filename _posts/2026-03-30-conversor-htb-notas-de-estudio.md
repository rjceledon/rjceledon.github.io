---
title: "Conversor - HTB Notas de Estudio"
date: 2026-03-30T23:18:30-04:00
categories:
  - cajas
tags:
  - htb
  - xslt
  - xml
  - gtfobins
  - cve
---
![image](https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/0b659c391f2803c247e79c77a3284f96.png){: width="100"}

# Conversor HTB - Notas de Estudio

## XSLT Injection - SQLite - Hash Cracking - CVE-2024-48990

### XSLT y XML: Conceptos Basicos

Se explora por que existe XSLT en lugar de modificar el XML directamente. XML es disenado para almacenar y transportar datos, no para mostrarlos. XSLT es una capa separada que define como presentar esos datos. El concepto es la separacion de responsabilidades: los datos se mantienen limpios e intactos, mientras que la hoja de estilos maneja la presentacion. Es analogo a CSS en HTML.

En cuanto a usos reales de XSLT, se identifican los siguientes contextos:

En sistemas empresariales y legados, las companias grandes con sistemas desde los anos 90 y 2000 usan XML/XSLT extensamente. Bancos, aseguradoras y sistemas de salud usan XSLT como traductor entre sistemas viejos y nuevos.

En generacion de documentos, se convierte data XML en PDFs o documentos Word, como facturas o reportes generados automaticamente.

En gobierno e industria, muchos sistemas gubernamentales y estandares como HL7 en salud usan XML con XSLT para transformar entre formatos.

En servicios web, los servicios SOAP, que fueron el estandar antes de REST, son basados en XML y usaban XSLT para transformar respuestas.

XSLT es considerada tecnologia legada hoy en dia, pero sigue viva en entornos empresariales que se mueven lentamente y tienen sistemas de hace 20 anos corriendo en produccion.

### El Procesador XSLT: libxslt y otros

El procesador XSLT es una libreria que corre en el servidor y toma los archivos XML y XSLT como entrada para producir la salida. Los procesadores mas comunes son:

libxslt es una libreria en C muy comun en sistemas Linux. Es lo que usa la libreria lxml de Python internamente, que es exactamente lo que usa la aplicacion Conversor.

Saxon es popular en entornos Java.

Xalan es otro procesador Java de Apache.

MSXML y .NET XslCompiledTransform son las implementaciones de Microsoft para Windows.

En el caso de Conversor, la aplicacion usa lxml de Python, que es un wrapper sobre libxslt. Al subir el XSLT malicioso, lxml se lo pasa a libxslt para procesarlo. libxslt soporta extensiones EXSLT, lo que habilita la escritura de archivos mediante el elemento exploit:document.

### Namespaces en XSLT: Como funcionan

Se analiza la linea xmlns:exploit="http://exslt.org/common" del archivo malicioso. El nombre exploit es completamente arbitrario. Se puede escribir xmlns:foo="http://exslt.org/common" y usar foo:document con el mismo resultado.

La URI http://exslt.org/common no es una URL que se descarga. Es unicamente un identificador unico. Es una convencion en XML/XSLT usar URLs como identificadores de namespace porque son globalmente unicos, pero nunca se descarga nada de esa direccion.

Lo que ocurre internamente es que libxslt tiene una tabla de busqueda con URIs conocidas mapeadas a sus modulos de extension integrados. Al ver http://exslt.org/common, encuentra la coincidencia y carga el modulo EXSLT common que incluye document. Si se cambia aunque sea una letra de la URI, no coincide con nada y libxslt trata el namespace como desconocido.

La misma logica aplica para xmlns:xsl="http://www.w3.org/1999/XSL/Transform". El procesador ya tiene toda la funcionalidad XSLT integrada y usa esta URI como clave para reconocer que elementos son instrucciones XSLT. El 1999 en la URL es el ano en que se finaliza XSLT 1.0 como estandar W3C.

El atributo extension-element-prefixes="exploit" es puramente cosmetico. Le dice al procesador que no incluya esa declaracion de namespace en el documento de salida. Sin el, el HTML generado tendria xmlns:exploit="http://exslt.org/common" en el elemento raiz. Removerlo no afecta en nada el funcionamiento del exploit.

### Extensiones EXSLT disponibles en libxslt

Los modulos EXSLT disponibles con sus namespaces son:

http://exslt.org/common incluye node-set(), object-type() y el elemento document para crear multiples archivos de salida. Este ultimo es el que se usa en el exploit.

http://exslt.org/math incluye funciones matematicas como min(), max(), random(), sin(), cos(), entre otras.

http://exslt.org/dates-and-times incluye funciones de fecha y hora.

http://exslt.org/sets incluye operaciones de conjuntos como difference(), intersection() y distinct().

http://exslt.org/strings incluye manipulacion de cadenas.

http://exslt.org/functions permite definir funciones de extension propias.

http://exslt.org/dynamic permite evaluacion dinamica de XPath, lo cual tambien es peligroso.

http://icl.com/saxon incluye extensiones Saxon como line-number().

Todos estos modulos se habilitan cuando lxml llama a exsltRegisterAll() en Python, lo cual hace por defecto. Para un setup mas seguro se deberian registrar unicamente los modulos necesarios.

### El elemento exsl:document y su uso

El elemento exsl:document es una extension EXSLT que permite escribir salida a un archivo. En el exploit se usa para escribir un script Python malicioso al filesystem del servidor.

El atributo method indica como formatear la salida. text escribe texto plano sin formato XML ni escaping, que es lo que se necesita para escribir codigo Python. xml escribe XML bien formado. html escribe HTML con manejo especifico como tags de autocierre.

Usar method="text" es critico para el exploit porque si se usara xml, los caracteres como < y > serian escapados, rompiendo el script Python.

En uso normal y legitimo, exsl:document existe para generar multiples archivos de salida desde una sola transformacion. Por ejemplo, a partir de un XML con 100 articulos, se puede generar un archivo HTML separado para cada articulo usando exsl:document dentro de un loop. Esto es algo que xsl:output estandar no puede hacer porque solo escribe una salida.

### Templates en XSLT: xsl:template y match

El elemento xsl:template define un bloque de instrucciones a ejecutar, similar a una funcion. El atributo match usa una expresion XPath para indicar cuando ejecutar ese template.

match="/" usa / que es XPath para la raiz del documento XML. Al ser la raiz unica en todo documento XML, este template siempre se ejecuta una vez al inicio del procesamiento. Es el punto de entrada del stylesheet, equivalente a main() en C o Python.

En un XSLT normal con multiples templates, el procesador recorre el arbol XML y aplica el template que coincide con cada nodo encontrado. El elemento xsl:apply-templates le indica al procesador que continue bajando por el arbol buscando mas coincidencias. Sin el, el procesador se detiene despues de ese template.

En el exploit, usar match="/" sin xsl:apply-templates es suficiente porque no se necesita recorrer el arbol. Simplemente se necesita que el elemento exsl:document se ejecute una vez para escribir el archivo malicioso.

### La vulnerabilidad XSLT Injection

Dado que el archivo XSLT subido no es sanitizado, la aplicacion resulta vulnerable a XSLT injection. La cadena de ataque funciona de la siguiente manera:

Se crea un archivo pwn.xslt malicioso que usa exsl:document para escribir un script Python en /var/www/conversor.htb/scripts/pwn.py. Ese script hace curl a la maquina atacante y pasa la respuesta a bash.

Se crea un archivo index.html en la maquina atacante con el payload de reverse shell.

Se levanta un listener con netcat en el puerto 9001 y un servidor HTTP con Python en el puerto 8000.

Se sube scan.xml junto con pwn.xslt a la aplicacion. Aproximadamente un minuto despues, el cron job ejecuta el script Python escrito, entregando una shell como www-data.

La razon por la que XSLT es esencialmente como permitir que usuarios suban y ejecuten su propio codigo es que XSLT es un lenguaje de programacion Turing-completo. Aceptar archivos XSLT de usuarios sin restricciones es una falla critica de seguridad.

### Escalada a fismathack: SQLite y Hash Cracking

Al enumerar el filesystem se encuentra la base de datos SQLite en /var/www/conversor.htb/instance/users.db. Al consultarla se obtienen las credenciales de los usuarios registrados, incluyendo el hash MD5 5b5c3ac3a1c897c94caad48e6c71fdec del usuario fismathack.

El hash es identificado como MD5 y crackeado con JohnTheRipper usando el wordlist rockyou.txt, obteniendo la contrasena Keepmesafeandwarm.

Con estas credenciales se obtiene acceso SSH como fismathack y se lee el flag de usuario en /home/fismathack/user.txt.

### CVE-2024-48990: needrestart y PYTHONPATH Hijacking

needrestart es una utilidad Linux que verifica que servicios necesitan ser reiniciados despues de actualizaciones del sistema. Frecuentemente corre con privilegios de root.

Lo que desencadena needrestart automaticamente en entornos reales incluye los hooks de apt y dpkg que llaman a needrestart despues de cualquier instalacion o actualizacion de paquetes, el servicio unattended-upgrades que instala actualizaciones de seguridad automaticamente en Ubuntu Server, y ejecucion manual por administradores.

El nucleo de CVE-2024-48990 esta en el archivo NeedRestart/Interp/Python.pm. El codigo vulnerable es el siguiente:

    my %e = nr_parse_env($pid);
    local %ENV;
    if(exists($e{PYTHONPATH})) {
        $ENV{PYTHONPATH} = $e{PYTHONPATH};
    }
    my ($pyread, $pywrite) = nr_fork_pipe2($self->{debug}, $ptable->{exec}, '-');
    print $pywrite "import sys\nprint(sys.path)\n";

La linea que lee /proc/pid/environ no es el problema en si. El error esta en copiar PYTHONPATH del proceso inspeccionado directamente al entorno propio sin ninguna validacion ni sanitizacion. Luego se lanza un nuevo interprete Python con un script hardcodeado que es seguro, pero Python carga importlib durante el startup antes de ejecutar ese script, y PYTHONPATH ya apunta al directorio malicioso del atacante.

La cadena de explotacion funciona de la siguiente manera:

Se compila lib.c como objeto compartido __init__.so. El nombre __init__ es especial porque Python trata cualquier directorio que lo contenga como un paquete importable.

Se coloca dentro de /tmp/malicious/importlib/ porque importlib es el modulo de la libreria estandar que needrestart importa durante su inspeccion.

Se ejecuta exploit.py con PYTHONPATH=/tmp/malicious en una terminal. Este proceso necesita mantenerse corriendo porque needrestart escanea /proc buscando procesos Python activos. Al encontrar el proceso de exploit.py, lee su entorno desde /proc/pid/environ y obtiene el PYTHONPATH malicioso.

Desde otra terminal se ejecuta sudo needrestart. Needrestart encuentra el proceso Python corriendo, lee su PYTHONPATH, lanza su propio Python con ese entorno, Python carga el importlib falso, se ejecuta __init__.so como root, y /bin/bash es copiado a /tmp/poc con el bit SUID.

Se ejecuta /tmp/poc -p para obtener shell de root. El flag -p le indica a bash que mantenga los privilegios elevados en lugar de descartarlos.

El fix en la version 3.8 simplemente deja de pasar PYTHONPATH como variable de entorno al nuevo proceso Python. En cambio, resuelve las rutas relativas al filesystem root del proceso inspeccionado via /proc/pid/root/.

### Metodo 2: needrestart GTFOBins

El segundo metodo de escalada no es un CVE sino una caracteristica legitima de needrestart. La flag -c permite cargar un archivo de configuracion personalizado. Dado que needrestart esta escrito en Perl y su archivo de configuracion tambien usa sintaxis Perl, cualquier codigo Perl valido en ese archivo sera ejecutado por el proceso.

    echo 'system("cp /bin/bash /tmp/poc; chmod u+s /tmp/poc")' > /tmp/cmd.conf
    sudo /usr/sbin/needrestart -c /tmp/cmd.conf

Esto funciona independientemente de la version de needrestart instalada. El problema es exclusivamente la regla de sudo sin restricciones de argumentos. La regla correcta deberia limitar los argumentos permitidos.

La diferencia fundamental entre ambos metodos es que CVE-2024-48990 es explotable sin ningun privilegio de sudo sobre needrestart, simplemente esperando a que alguien con privilegios lo ejecute automaticamente. El metodo GTFOBins requiere acceso de sudo a needrestart pero funciona en cualquier version.

### Como needrestart encuentra procesos Python: Implementacion

El proceso interno de needrestart para encontrar procesos Python funciona de la siguiente manera:

Primero usa el modulo Perl Proc::ProcessTable para iterar sobre cada entrada en /proc/, obteniendo todos los procesos corriendo en el sistema.

Para cada proceso, lee /proc/pid/exe y lo compara contra la regex /usr/(local/)?bin/python([23][.\d]*)?$. Solo los procesos corriendo con un binario Python en rutas estandar son reconocidos. Usar un binario Python en una ruta no estandar evade la deteccion.

Al encontrar un proceso Python, escanea el archivo fuente buscando lineas import y from para determinar que modulos usa el script.

Finalmente lee /proc/pid/environ del proceso encontrado y procede con la logica vulnerable descrita anteriormente.

Una nota adicional: en la version 3.8 se corrigen simultaneamente cuatro CVEs. Ademas de CVE-2024-48990 con PYTHONPATH, se corrige CVE-2024-48992 que es exactamente el mismo problema pero para Ruby con la variable RUBYLIB, CVE-2024-48991 que es una condicion de carrera en la evaluacion de /proc/PID/exec, y CVE-2024-11003 que elimina el uso de Module::ScanDeps para prevenir LPE en Perl.

Gracias!

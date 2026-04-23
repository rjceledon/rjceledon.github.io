---
title: "Support - HTB - Notas de Estudio"
date: 2026-04-22T00:00:00-04:00
categories:
  - cajas
tags:
  - htb
  - ldap
  - active-directory
  - kerberos
  - rbcd
  - smb
  - winrm
---

# Support HTB - Notas de Estudio

## Synopsis

Maquina Windows de dificultad Easy. El vector de entrada es un SMB share con autenticacion anonima que contiene un ejecutable .NET. Reverse engineering del binario revela credenciales LDAP hardcodeadas encriptadas con XOR. Con esas credenciales se enumera el directorio LDAP y se encuentra una password en el campo `info` de un usuario. Ese usuario tiene acceso WinRM. La escalada de privilegios explota un `GenericAll` sobre el Domain Controller via un ataque de Resource Based Constrained Delegation (RBCD).

---

## Decryption XOR — UserInfo.exe

### Como funciona el algoritmo de decryptado?

El binario tiene una clase `Protected` con una password encriptada en Base64 y una key `"armando"`. El proceso es:

1. Base64 decode de `enc_password` hacia un array de bytes
2. Por cada byte: XOR con el byte correspondiente de la key ciclando con `% key.Length`
3. Segundo XOR con la constante `0xDF` (223 en decimal)
4. Convertir el resultado a string

```csharp
array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
```

### Por que XOR?

XOR es reversible — aplicarlo dos veces con el mismo valor devuelve el original. No hay suma ni carry, es pura operacion de bits. Si los bits son distintos el resultado es 1, si son iguales es 0.

```
208  =  1 1 0 1 0 0 0 0
 97  =  0 1 1 0 0 0 0 1
XOR  =  1 0 1 1 0 0 0 1  = 177
```

### Que hace `key[i % key.Length]`?

Como la key `"armando"` tiene 7 caracteres pero el array encriptado tiene 36 bytes, el operador `%` (modulo) hace que la key cicle:

```
i=0  → 0 % 7 = 0 → 'a'
i=7  → 7 % 7 = 0 → 'a'  ← reinicia!
i=8  → 8 % 7 = 1 → 'r'  ← continua ciclando
```

### La `u` en `0xDFu` cambia algo?

No en el resultado. `u` solo indica que el literal es un `unsigned int` — es un hint para el compilador para evitar comportamientos raros con signos durante operaciones de bits. El valor sigue siendo 223 y el XOR produce el mismo resultado.

### Script Python equivalente

```python
import base64
from itertools import cycle

enc_password = base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E")
key = b"armando"

res = ''
for e, k in zip(enc_password, cycle(key)):
    res += chr(e ^ k ^ 223)

print(res)
# nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

---

## LDAP — Conceptos Fundamentales

### LDAP es una base de datos?

LDAP es un protocolo para hablar con Active Directory, no una base de datos en si. La relacion es:

```
Active Directory  ←  la base de datos real
LDAP              ←  el lenguaje para hablar con ella

igual que:
MySQL             ←  la base de datos real
SQL               ←  el lenguaje para hablar con ella
```

### Como es la estructura del arbol?

En vez de tablas planas, LDAP usa una estructura de arbol similar a un filesystem:

```
DC=htb
  └── DC=support
        ├── CN=Users        ← usuarios y grupos custom
        │     ├── CN=support
        │     └── CN=Shared Support Accounts
        ├── CN=Computers
        │     └── CN=DC
        ├── CN=Builtin      ← grupos default de Windows
        └── CN=Schema       ← define las reglas del directorio
```

### Que atributos son importantes para atacantes?

```
sAMAccountName      ← username real
memberOf            ← grupos a los que pertenece
adminCount          ← =1 significa cuenta admin protegida
servicePrincipalName← kerberoastable si esta presente
msds-allowedtoactonbehalfofotheridentity ← RBCD
info / description / comment ← campos de texto libre,
                               admins ponen passwords aqui!
```

### Donde viven los grupos custom vs los default?

```
CN=Builtin  → grupos default creados por el OS
CN=Users    → grupos y usuarios creados por admins
```

`Shared Support Accounts` es un grupo custom — por eso no aparece en `CN=Builtin`.

### Por que no se ve `nTSecurityDescriptor` en Apache Directory Studio?

Es un atributo operacional — LDAP no lo devuelve por default. Hay que pedirlo explicitamente:

```bash
ldapsearch -H ldap://support.htb \
  -D ldap@support.htb \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "CN=DC,OU=Domain Controllers,DC=support,DC=htb" \
  -s base \
  nTSecurityDescriptor
```

El flag `-s base` solo mira el objeto exacto especificado en `-b`, sin buscar hijos. Aun asi, usuarios no privilegiados normalmente no pueden leerlo — esta protegido por `AdminSDHolder` que resetea los permisos cada 60 minutos en objetos sensibles como DCs.

Otras categorias de atributos ocultos:

```
Operacionales    → manejados por el servidor, ocultos por default
                   nTSecurityDescriptor, canonicalName

Confidenciales   → requieren permisos especiales
                   unicodePwd (nunca se devuelve)

Construidos      → computados on the fly
                   tokenGroups, msDS-ResultantPSO
```

### Donde estan guardados los permisos `GenericAll`?

No como un atributo visible normal. Estan dentro de `nTSecurityDescriptor` como un blob binario que contiene el DACL (Discretionary Access Control List). Cada ACE (Access Control Entry) dentro dice:

```
WHO  → Shared Support Accounts
WHAT → GenericAll (0x000F01FF)
ON   → este objeto (el DC)
```

Por eso BloodHound existe — parsea ese binario en todos los objetos y dibuja las relaciones visualmente. Sin el, habria que parsear manualmente ACLs binarias en cientos de objetos.

### Que hay en CN=DomainDnsZones que interesa a atacantes?

Contiene todos los registros DNS del dominio. Permite mapear la red interna sin hacer un solo scan:

```
dc.support.htb      → 10.129.178.26
fileserver.htb      → 10.129.178.50
backup              → objetivo interesante
sqlserver           → objetivo interesante
```

Los registros DNS se guardan en un atributo binario llamado `dnsRecord` — por eso se ven como binario en Apache Directory Studio. La herramienta `adidnsdump` los parsea y presenta de forma legible.

### Se puede deshabilitar LDAP teniendo AD activo?

Tecnicamente si, pero es practicamente imposible porque AD depende de LDAP internamente para domain joins, Group Policy, Kerberos, replicacion entre DCs, etc. En vez de deshabilitarlo, se endurece:

```
Deshabilitar anonymous binding
Forzar LDAPS (puerto 636)
Requerir LDAP signing
ACLs granulares sobre atributos sensibles
```

### Como se deshabilita el anonymous binding?

Via Group Policy (recomendado para que aplique a todos los DCs automaticamente):

```
Group Policy Management
  → Default Domain Controllers Policy
  → Computer Configuration
  → Windows Settings
  → Security Settings
  → Local Policies
  → Security Options
    → "Domain controller: LDAP server signing requirements"
       → Require signing
```

O via registro directamente en el DC:

```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
  LDAPServerIntegrity = 2  (0=none, 1=negotiated, 2=required)
```

O via ADSI Edit en `CN=Directory Service` modificando el atributo `dsHeuristics` (posicion 7 del string).

---

## SMB — Acceso Anonimo

### Por que funciono el acceso anonimo al share?

El share `support-tools` tenia permisos para el grupo `Everyone`. En Windows, `Everyone` incluye usuarios anonimos cuando el anonymous binding esta habilitado. La solucion es remover `Everyone` y usar grupos especificos.

### Como se deshabilitan las null sessions en SMB?

Via Group Policy:

```
Security Options:
  → "Network access: Let Everyone permissions apply
     to anonymous users"                          → Disabled
  → "Network access: Restrict anonymous access
     to Named Pipes and Shares"                   → Enabled
  → "Network access: Do not allow anonymous
     enumeration of SAM accounts and shares"      → Enabled
```

### Capas para endurecer SMB correctamente

```
1. Remover Everyone de permisos de shares
2. Deshabilitar null sessions via GPO
3. Deshabilitar SMBv1 completamente
4. Requerir SMB signing (previene relay attacks)
5. Bloquear puerto 445 en firewall para acceso externo
```

---

## WinRM

### Como funciona WinRM tecnicamente?

WinRM (Windows Remote Management) es basicamente SSH para Windows. Usa el protocolo WSMan que es SOAP sobre HTTP. SOAP es XML estructurado viajando en HTTP POST requests.

```
Puertos:
5985 → HTTP  (sin encriptacion)
5986 → HTTPS (necesita certificado)
```

### Que es SOAP?

SOAP = Simple Object Access Protocol. Es un estandar para estructurar mensajes XML para que sistemas distintos puedan comunicarse independientemente del lenguaje o sistema operativo. Cada mensaje tiene:

```xml
<Envelope>
  <Header>  ← metadata: destino, auth, message ID, timeout
  <Body>    ← el contenido real: el comando, los datos
</Envelope>
```

Microsoft eligio SOAP para WinRM porque era el estandar enterprise de la epoca (early 2000s) y funciona a traves de firewalls sobre HTTP normal. Hoy es considerado verboso comparado con REST, pero WinRM lo sigue usando por compatibilidad con millones de deployments existentes.

### Se pueden hacer conexiones raw a WinRM?

Si. WinRM escucha HTTP en 5985 entonces se puede interactuar directamente:

```bash
# verificar si WinRM responde (sin autenticacion)
curl -v http://support.htb:5985/wsman

# esto devuelve la version de Windows sin autenticacion!
# es un information disclosure por diseno del protocolo
```

Con telnet tambien funciona para verificar si el puerto esta abierto — si conecta, WinRM esta corriendo.

### Como funciona la autenticacion NTLM (el challenge)?

NTLM es un sistema challenge-response — el servidor verifica que conoces la password sin que la password viaje por la red:

```
1. Cliente → Servidor: "quiero autenticarme como support\support"
2. Servidor → Cliente: challenge (numero random: 8A3F92BC...)
3. Cliente: password_hash + challenge → resultado encriptado → envia
4. Servidor: mismo calculo con hash guardado → compara → autentica
```

El challenge es diferente cada vez, entonces capturas de trafico no se pueden reutilizar. Las debilidades de NTLM son Pass the Hash, NTLM Relay, y crackeo offline del challenge capturado. Por eso Kerberos lo reemplazo en entornos modernos, aunque NTLM sigue soportado por backwards compatibility.

### Como se habilita o deshabilita WinRM?

```powershell
# habilitar todo automaticamente
Enable-PSRemoting -Force

# deshabilitar
Disable-PSRemoting -Force
Stop-Service WinRM
Set-Service WinRM -StartupType Disabled
```

Via Group Policy:

```
Computer Configuration
  → Administrative Templates
  → Windows Components
  → Windows Remote Management (WinRM)
  → WinRM Service
    → "Allow remote server management through WinRM" → Enabled/Disabled
```

Para endurecer en vez de deshabilitar: usar HTTPS (5986), restringir el grupo `Remote Management Users`, y limitar IPs origen via firewall rules.

---

## Kerberos — Tickets y Autenticacion

### Que es un ticket de Kerberos?

En vez de enviar passwords por la red, Kerberos usa tickets — blobs encriptados que prueban identidad. Analogia con un parque de diversiones:

```
Sin Kerberos:
  cada atraccion → mostrar pasaporte → verificar con HQ → entrar
  lento, el pasaporte viaja por todos lados

Con Kerberos:
  entrada → mostrar pasaporte UNA VEZ → recibir pulsera
  cada atraccion → mostrar pulsera → entrar directamente
  el pasaporte nunca sale del bolsillo!
```

Los tres actores del sistema:

```
KDC (Key Distribution Center) ← la boleteria, corre en el DC
Client                         ← vos
Service                        ← lo que queres acceder (CIFS, LDAP, etc)
```

### Que son TGT y TGS?

**TGT (Ticket Granting Ticket):** "un ticket que te otorga mas tickets." No da acceso a ningun servicio directamente — es prueba de identidad para pedir TGS al KDC. La pulsera del parque.

**TGS (Ticket Granting Service ticket):** ticket emitido por el componente Ticket Granting Service del KDC. Da acceso a un servicio especifico. Los pases individuales de cada atraccion.

El KDC tiene dos componentes:

```
AS  (Authentication Service)  ← emite TGTs
TGS (Ticket Granting Service) ← emite tickets de servicio
```

El nombre TGS es ambiguo porque se usa para referirse tanto al componente como al ticket que emite ese componente. En la RFC original se llama simplemente "service ticket".

### Como funciona el flujo completo?

**Fase 1 — obtener TGT (AS-REQ / AS-REP):**

```
Cliente → KDC:
  AS-REQ con PA-ENC-TIMESTAMP:
  timestamp encriptado con NTLM hash del usuario
  → prueba que conocemos la password sin enviarla

KDC → Cliente:
  AS-REP contiene DOS partes separadas:

  ticket TGT:
    encriptado con el hash de krbtgt
    → cliente lo CARGA pero NO puede abrirlo
    → opaco, como un sobre sellado
    → solo el KDC puede abrirlo

  enc-part:
    encriptado con el hash del CLIENTE
    → cliente lo descifra
    → extrae la session key
    → usa esa key para encriptar futuros requests al KDC
```

Cuando la gente dice "tengo un TGT" significa que tiene ambas cosas: el blob sellado Y la session key.

```
TGT blob    = sobre sellado con carta de recomendacion
              lo cargas pero no puedes abrirlo
              solo lo entregas al KDC cuando necesitas algo

session key = secreto compartido entre cliente y KDC
              establecido durante autenticacion
              encripta tus futuros requests
```

**Fase 2 — obtener ticket de servicio (TGS-REQ / TGS-REP):**

```
Cliente → KDC:
  "quiero acceder a CIFS en dc.support.htb"
  presenta el TGT como prueba de identidad

KDC lee el TGT (puede abrirlo con su propia key):
  "valido, el cliente es quien dice ser"

KDC → Cliente:
  TGS ticket especificamente para CIFS en dc.support.htb
  encriptado con la key del servicio CIFS
  → el cliente lo carga pero tampoco puede abrirlo
  → solo el servicio CIFS puede descifrarlo
```

**Fase 3 — acceder al servicio:**

```
Cliente → Servicio CIFS:
  presenta el TGS ticket

CIFS descifra con su propia key:
  lee el PAC adentro
  ve: usuario = Administrator, Domain Admin
  otorga acceso!
```

La password nunca viajo por la red en ningun momento.

### Que es PA-ENC-TIMESTAMP y por que previene ataques?

`PA` = Pre-Authentication. Son campos extra adjuntos a los requests de Kerberos para probar identidad o proveer contexto adicional al KDC.

El KDC intenta descifrar el timestamp con el hash guardado:

```
resultado es timestamp valido → password correcta → autenticado
resultado es basura           → password incorrecta → rechazado
```

El timestamp ademas debe estar dentro de 5 minutos del reloj del DC. Si hay mas diferencia:

```
Error: KRB_AP_ERR_SKEW - clock skew too great
```

Por eso en ataques Kerberos a veces hay que sincronizar el reloj primero:

```bash
ntpdate dc.support.htb
```

El timestamp cambia cada request, entonces capturas de trafico no pueden reutilizarse.

### Que es el PAC?

```
PAC = Privilege Attribute Certificate
→ embebido dentro de cada ticket Kerberos
→ contiene:
   username
   SID del usuario
   memberships de grupos
   privilegios
   todo firmado por el KDC para prevenir tampering

cuando el servicio CIFS del DC recibe el ticket:
→ lo descifra con su propia key
→ lee el PAC
→ ve: usuario = Administrator, miembro de Domain Admins
→ otorga acceso total
```

### Que es S4U2?

```
S4U = Service For User
→ extension de Kerberos inventada por Microsoft (RFC 4559)
→ permite a un servicio obtener tickets en nombre de un usuario
→ dos sub-extensiones:

S4U2Self  = Service For User to Self
            el servicio pide un ticket como si el usuario
            lo hubiera pedido para acceder al mismo servicio

S4U2Proxy = Service For User to Proxy
            usa el ticket de S4U2Self como evidencia
            para pedir un ticket para otro servicio destino
```

Se implementa como un campo extra `PA-FOR-USER` en el TGS-REQ:

```
padata:
  └── PA-FOR-USER (type 129):
        ├── userName: Administrator
        ├── userRealm: SUPPORT.HTB
        └── cksum: checksum firmado con session key
                  → previene spoofing del username
                  → sin esto cualquiera podria poner
                     cualquier nombre en el campo
```

S4U2Self y S4U2Proxy no son tipos especiales de ticket — son extensiones al TGS-REQ standard. El ticket resultante es un TGS normal que parece identico a uno que el propio Administrator hubiera pedido. El DC no puede distinguirlos.

---

## RBCD — Resource Based Constrained Delegation

### Que significa el nombre?

**Delegation:** un servicio puede impersonar a un usuario ante otro servicio sin que el usuario este presente.

**Constrained:** limitado — solo puede impersonar a servicios especificos predefinidos, no a cualquier servicio del dominio.

**Resource Based:** el RECURSO (el objeto al que se accede) decide quien puede impersonarlo. Se configura en el atributo `msds-allowedtoactonbehalfofotheridentity` del objeto destino, no de forma centralizada por el admin.

### Por que se llama `msds-allowedtoactonbehalfofotheridentity`?

```
msds          = Microsoft Directory Services
allowed       = permitido / autorizado
toacton       = actuar sobre
behalfof      = en nombre de
otheridentity = otra identidad / principal

significado completo:
"que principals tienen permitido actuar
 en nombre de otras identidades ante este objeto"
```

### Por que no se ve en herramientas regulares de PowerShell?

No es que no este disponible — es un atributo no-default. El modulo AD lo devuelve si se pide explicitamente:

```powershell
Get-ADComputer -Identity DC `
  -Properties msds-allowedtoactonbehalfofotheridentity
```

El problema es que devuelve un blob binario ilegible. PowerView parsea ese security descriptor y lo presenta de forma legible con SIDs resueltos a nombres. Por eso se usa PowerView para este caso especifico, no porque sea el unico camino.

### Por que se chequea si el atributo esta vacio antes del ataque?

Tecnicamente con GenericAll se puede sobreescribir igual. Pero si ya tiene un valor, significa que hay una delegacion legitima configurada:

```
sobreescribimos con FAKE-COMP01
→ el ataque funciona
→ PERO rompemos la delegacion legitima
→ alguna aplicacion de produccion deja de funcionar
→ el equipo de IT investiga
→ nos detectan
```

La practica correcta si ya habia un valor: guardarlo, sobreescribir, ejecutar el ataque, restaurar el valor original para no dejar rastros.

### Cual fue la misconfiguracion en este box?

```
Shared Support Accounts → GenericAll → DC object

GenericAll incluye WriteProperty sobre todos los atributos
→ incluye msds-allowedtoactonbehalfofotheridentity
→ podemos escribir quien puede impersonar usuarios al DC
→ escribimos FAKE-COMP01 (maquina que creamos nosotros)
→ KDC confia en FAKE-COMP01 para impersonar a Administrator
→ comprometemos el dominio completo
```

`GenericAll` en un objeto de tipo COMPUTER es particularmente peligroso comparado con `GenericAll` en un objeto USER porque habilita la configuracion de delegacion. El valor hex `0x000F01FF` representa la suma de todos los permisos posibles — Create, Delete, Read, Write, WriteDACL, WriteOwner, etc.

### Por que podemos crear FAKE-COMP01?

Por el atributo `ms-DS-MachineAccountQuota = 10`. Por default cualquier usuario autenticado puede agregar hasta 10 computadoras al dominio. Windows NO verifica que la maquina exista fisicamente — no hace ping, no verifica DNS, no chequea nada. Solo crea el objeto en AD.

Esta es una misconfiguracion legacy de Windows 2000 pensada para small businesses sin IT admin dedicado. La recomendacion actual es setearlo a 0.

Setear a 0 solo bloquea usuarios regulares. Domain Admins y Account Operators no se ven afectados. Si existe una cuenta pre-staged en ADUC, el join al dominio igual funciona con quota en 0 porque no necesita crear un objeto nuevo.

### Por que no usar `New-ADComputer` en vez de PowerMad?

`New-ADComputer` va por la "puerta principal" — chequea permisos de admin antes de proceder y frecuentemente rechaza usuarios regulares aunque el quota lo permita. Ademas requiere el modulo AD instalado, que no esta en todas las maquinas.

PowerMad va por la "puerta lateral" — hace llamadas LDAP directas al DC explotando el quota sin pasar por los checks del modulo AD. Funciona desde cualquier maquina en la red sin necesitar el modulo instalado.

### Por que una maquina tiene password?

Las maquinas tienen su propia identidad en el dominio separada del usuario:

```
cada 30 dias automaticamente:
→ Windows genera una password random de 120 chars unicode
→ la guarda en LSA secrets (registro encriptado, solo SYSTEM puede leer)
→ el DC guarda el hash en AD
→ completamente transparente, el usuario nunca la ve
```

Esta password es usada por Kerberos para encriptar tickets de servicios como `HOST/` y `CIFS/`. Sin ella Kerberos no funciona para esa maquina.

Las passwords de maquinas generadas por Windows nunca se crackean en la practica — 120 caracteres unicode random es un keyspace astronomicamente grande. Por eso en el ataque creamos FAKE-COMP01 con una password que nosotros elegimos (Password123) para siempre saber cual es.

### Como fluye el ataque completo?

```
GenericAll sobre DC
  ↓
escribir FAKE-COMP01 en msds-allowedtoactonbehalfofotheridentity
  ↓
Password123 → MD4 → NTLM hash (rc4_hmac)
  ↓
AS-REQ con timestamp encriptado
  ↓
TGT para FAKE-COMP01$ + session key
  ↓
S4U2Self TGS-REQ con PA-FOR-USER(Administrator)
  ↓
ticket: Administrator → FAKE-COMP01$
  ↓
S4U2Proxy TGS-REQ + ticket anterior + chequeo msds
  ↓
ticket: Administrator → cifs/dc.support.htb (con PAC!)
  ↓
base64 → ticket.kirbi → ticketConverter.py → ticket.ccache
  ↓
KRB5CCNAME=ticket.ccache psexec.py -k -no-pass
  ↓
DC lee PAC → Administrator → acceso a ADMIN$ share
  ↓
servicio creado → corre como SYSTEM
  ↓
shell!
```

### Por que MD4 para el hash?

NTLM fue disenado a principios de los 90s cuando MD4 era el estandar. Nunca fue actualizado a pesar de MD4 estar matematicamente roto. El legado permanece por backwards compatibility.

### Por que CIFS y no otro servicio?

psexec necesita especificamente CIFS porque opera en dos pasos que ambos dependen del mismo protocolo:

```
1. sube el ejecutable a ADMIN$ share → via CIFS
2. habla con el Service Control Manager via named pipes
   → los named pipes viajan SOBRE CIFS!
```

Un ticket LDAP, HTTP u HOST no hubiera funcionado con psexec. La herramienta dicta el tipo de ticket necesario.

---

## Pass the Ticket y Named Pipes

### Que es Pass the Ticket?

Normalmente los tickets de Kerberos viven en memoria en el proceso LSASS. Pass the Ticket significa:

```
robar o generar un ticket
→ inyectarlo en la cache de tickets de tu sesion
→ ahora estas autenticado como esa identidad
→ sin necesitar la password
```

### Por que convertir kirbi a ccache?

```
.kirbi  → formato Windows (Rubeus, Mimikatz)
.ccache → formato Linux/MIT Kerberos (impacket)

ticketConverter.py solo reformatea el contenedor
el ticket adentro es exactamente el mismo datos
```

### Que es un named pipe?

Un named pipe es un canal de comunicacion con nombre entre procesos, accesible como si fuera un archivo:

```
local:  \\.\pipe\nombre
remoto: \\servidor\pipe\nombre   ← viaja sobre CIFS!
```

A diferencia de un pipe regular (sin nombre, temporal, solo entre procesos relacionados), un named pipe persiste independientemente y cualquier proceso puede conectarse a el, incluso desde otra maquina en la red.

### Como psexec usa named pipes para dar una shell?

psexec NO sube un reverse shell. Sube un ejecutable de Windows Service con nombre random (en el writeup: `NeYKdoVH.exe`) que hace lo siguiente internamente:

```
1. crea named pipe con nombre random
2. lanza cmd.exe con stdin/stdout/stderr = el pipe
3. impacket se conecta al pipe via CIFS
4. lo que escribes → stdin de cmd.exe → se ejecuta como SYSTEM
5. el output de cmd.exe → vuelve por el pipe → ves el resultado
```

`cmd.exe` corre realmente en la victima. El pipe solo conecta su stdio a vos. Es como sentarte fisicamente en el teclado de esa maquina.

### Por que named pipe es mas stealth que reverse shell?

```
reverse shell:
  → la victima inicia conexion SALIENTE hacia el atacante
  → firewall ve trafico outbound a IP externa
  → muy sospechoso
  → la IP del atacante queda en los logs

named pipe via CIFS:
  → el atacante inicia la conexion hacia la victima (inbound)
  → sobre puerto 445 (SMB normal)
  → parece trafico legitimo de file share
  → mucho mas dificil de distinguir de actividad admin normal
```

### Por que el resultado es SYSTEM y no Administrator?

psexec crea un Windows Service. Los servicios corren como `NT AUTHORITY\SYSTEM` por default. SYSTEM es en algunos contextos mas poderoso que Administrator en la maquina local — por eso el output de `whoami` muestra `nt authority\system`.

### Tickets famosos en ataques de AD

```
Pass the Ticket:   inyectar ticket valido en sesion
Golden Ticket:     forjar TGT con hash de krbtgt → valido 10 años,
                   funciona incluso si cambian la password del usuario
Silver Ticket:     forjar TGS de servicio especifico usando hash del
                   service account → nunca toca el KDC, mas dificil de detectar
Overpass the Hash: usar NTLM hash para pedir un ticket Kerberos real
                   → convierte un ataque de hash en un ataque de ticket
```

---

## Hardening — Resumen de Mitigaciones

```
ms-DS-MachineAccountQuota = 0
  → previene RBCD attack por usuarios regulares
  → no afecta Domain Admins ni pre-staged accounts

nTSecurityDescriptor auditado regularmente
  → revisar GenericAll sobre objetos criticos como DCs
  → BloodHound puede hacer este analisis automaticamente

LDAP anonymous binding deshabilitado
  → sin enumeracion posible sin credenciales validas

SMBv1 deshabilitado, SMB signing requerido
  → previene relay attacks

WinRM sobre HTTPS (5986) unicamente
  → encriptacion en transito

Passwords nunca en campos info/description/comment
  → el bug mas evitable de este box, pura negligencia

OSConfig en Windows Server 2025
  → aplica mas de 300 security settings automaticamente
  → incluye TLS 1.2+, SMB 3.0+, Secured-Core
  → drift control: corrige desviaciones cada 4 horas
  → NO cubre ms-DS-MachineAccountQuota (hay que setearlo manualmente)
  → NO reemplaza GPOs, es complementario
```

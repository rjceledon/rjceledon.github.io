---

title: "Principal - HTB - Notas de Estudio"
date: 2026-03-28T22:03=:30-04:00
categories:

* cajas
tags:
* htb
* jwt
* jwk
* web
* sshd

---

![image](https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/a3257c109bddf7358350a2cf02b8ae81.png){: width="100"}

# Principal HTB - Notas de Estudio

## CVE-2026-29000 — pac4j-jwt Authentication Bypass

### Por que funciona la vulnerabilidad?
El servidor esta configurado con JWE (encryption) y JWS (signature verification) al mismo tiempo. El bug esta en un null check. Cuando el inner token es un PlainJWT (`"alg":"none"`), `toSignedJWT()` retorna null, y el bloque de verificacion de firma se saltea completamente. El servidor valida el cryptographic envelope (el JWE se desencripta bien) pero nunca valida el identity claim adentro.

### Que esta faltando?
Dos checks que deberian existir pero no estan:
- Un rechazo explicito de PlainJWT despues de desencriptar
- Verificacion de firma incondicional sin importar el tipo de JWT

### Si pac4j acepta PlainJWT legitimamente, quien deberia rechazarlo?
La aplicacion. La libreria da los building blocks pero el desarrollador es responsable de aplicar la propia security policy. Un simple check `instanceof PlainJWT` antes de pasarlo al authenticator hubiera prevenido esto.

### Que significan JWE y JWS?
- **JWT** — JSON Web Token (termino general)
- **JWS** — JSON Web Signature (token firmado)
- **JWE** — JSON Web Encryption (token encriptado)

### Puede un JWT ser uno y no el otro?
Si. Las cuatro combinaciones son:
- **JWS only** — firmado, payload legible. El mas comun en la practica.
- **JWE only** — encriptado, payload ilegible. Sin garantia de autenticidad si la public key esta expuesta.
- **JWS + JWE** — firmado y luego encriptado. El mas seguro, pero mas complejo.
- **PlainJWT** — ni firmado ni encriptado. Casi nunca legitimo en produccion.

### Por que es poco comun JWS + JWE?
La mayoria de los JWTs no necesitan ser secretos, solo necesitan ser a prueba de tampering. El payload normalmente tiene datos no sensibles como username y role que el servidor ya conoce. La firma sola es suficiente para la mayoria de los casos de auth.

### Cuando se necesitaria JWE?
Cuando el token contiene datos genuinamente sensibles que el cliente no deberia ver: PII, detalles internos del sistema, o tokens que pasan por intermediarios no confiables.

### El endpoint JWKS expuso una encryption key, es eso normal?
No. Los endpoints JWKS normalmente exponen signing public keys para que los clientes puedan verificar firmas. Exponer una encryption public key es inusual porque significa que cualquiera puede encriptar contenido arbitrario para el servidor. En un setup estandar de OAuth/OIDC como Microsoft Entra, solo se vera keys con `"use":"sig"`.

### Como identificas si una key de JWKS es para signing o encryption?
Observando el campo `use`:
- `"use":"sig"` — signing key
- `"use":"enc"` — encryption key

Si no esta, se debe fijar en el `kid` para hints (ej. `enc-key-1`) o investigar el auth flow de la app. Un campo `use` ausente es en si mismo un finding.

### JWE siempre necesita una firma?
No siempre. Si el servidor encripta con su propia private key y la public key nunca se expone, la encriptacion sola provee integridad. Pero si la public key esta expuesta (como via JWKS), cualquiera puede encriptar contenido arbitrario, haciendo la firma obligatoria para verificar autenticidad.

### Como funciona el exploit paso a paso?
1. Fetch de la RSA public key desde `/api/auth/jwks`
2. Crear un PlainJWT con `"alg":"none"` y claims forjados (`sub: admin, role: ROLE_ADMIN`)
3. Envolverlo en un JWE valido encriptado con la public key del servidor
4. Enviarlo como Bearer token, el servidor desencripta bien pero saltea la verificacion de firma

### Por que el PlainJWT necesita el trailing dot?
Nimbus JOSE (la libreria que usa pac4j internamente) chequea explicitamente que el tercer segmento este vacio. Sin el trailing dot, el parser tira un ParseException antes de llegar al codigo vulnerable. El exploit fallaria silenciosamente.

### Por que esta vulnerabilidad paso desapercibida?
- La combinacion JWS + JWE es poco comun, la mayoria de los usuarios nunca estuvieron expuestos
- El null check parece seguro a primera vista
- JWE da una falsa sensacion de seguridad ("el payload esta encriptado, asi que esta bien")
- PlainJWT es un concepto legitimo del spec de JWT, asi que la libreria lo maneja, solo que incorrectamente

---

## JWE Encryption Internals

### Por que se usan dos keys en JWE?
JWE usa dos keys:
- **CEK (Content Encryption Key)** — random, efimera, generada fresca por token. Encripta el payload real.
- **KEK (Key Encryption Key)** — secreto compartido permanente. Encripta el CEK.

El CEK no se guarda en ningun lado — viaja dentro del token como el segmento `encrypted_key`, envuelto por el KEK. El servidor lo desenvuelve cuando lo necesita, lo usa una vez, y lo descarta.

### Cuales son los 5 segmentos del JWE?
```
header . encrypted_key . iv . ciphertext . auth_tag
```
- **header** — info de algoritmos, siempre legible
- **encrypted_key** — CEK envuelto con KEK
- **iv** — nonce random para AES-GCM
- **ciphertext** — el payload encriptado (el JWS en este caso)
- **auth_tag** — check de integridad, la desencriptacion falla si fue tampered

### Por que jwt.io rechaza tokens JWE?
jwt.io solo entiende JWS (tokens de 3 partes). JWE tiene 5 partes separadas por dots — jwt.io ve un formato inesperado y lo rechaza. Para inspeccionar un JWE, decodifica solo el primer segmento (el header siempre es base64 en texto plano) o usa una herramienta como mkjwt.io.

### Como envia el browser los tokens de session storage?
A diferencia de las cookies, los valores de session storage nunca se envian automaticamente. La app JavaScript lee explicitamente el token y lo adjunta como header `Authorization: Bearer` en cada request a la API. El servidor ve un Bearer token estandar, el mecanismo que lo puso ahi es invisible a nivel HTTP.

---

## Privilege Escalation — SSH CA Certificate Forgery

### Como funciona la autenticacion por SSH CA?
En vez de matchear la public key contra `authorized_keys`, el servidor chequea si el certificado fue firmado por una CA de confianza (`TrustedUserCAKeys`). Esto permite gestion centralizada de accesos sin distribuir public keys a cada servidor.

### Cual es la mala configuracion?
`TrustedUserCAKeys` esta seteado pero `AuthorizedPrincipalsFile` no esta configurado. Sin el, sshd solo chequea:
1. El certificado fue firmado por la CA de confianza? (Si)
2. El principal en el certificado matchea el username destino? (Si)

No hay whitelist check — entonces cualquier principal puede ser forjado.

### Que hubiera prevenido AuthorizedPrincipalsFile?
Desacoplar "lo que el certificado dice" de "lo que realmente esta permitido." Incluso teniendo la capacidad de firmar con la CA, el principal debe estar listado explicitamente para ese usuario. Un archivo bien configurado para root listaria identidades de servicio especificas, no `root` en si mismo.

### Que es AuthorizedPrincipalsCommand?
Una alternativa dinamica al archivo estatico. sshd ejecuta un script en cada intento de login y usa su output como la lista de principals permitidos. Util en entornos grandes donde el acceso cambia frecuentemente, el script puede consultar una base de datos o API y retornar principals en tiempo real. Corre como un usuario de bajo privilegio (tipicamente `nobody`) via `AuthorizedPrincipalsCommandUser`.

### Que habilita el certificate auth en primer lugar?
`PubkeyAuthentication yes`. Sin esto, sshd ignora tanto las public keys como los certificados. Los cuatro directives juntos crean la vulnerabilidad:
```
PubkeyAuthentication yes          → habilita certificate auth
TrustedUserCAKeys ca.pub          → confia en nuestra CA
PermitRootLogin prohibit-password → root permitido via certificado
(no AuthorizedPrincipalsFile)     → sin whitelist de principals
```

### Que hace cada flag en los comandos del exploit?

**Key generation:**
```bash
ssh-keygen -t ed25519 -f /tmp/pwn -N ""
```
- `-t ed25519` — algoritmo de key (cualquier tipo funciona, irrelevante para la vulnerabilidad)
- `-f /tmp/pwn` — path de output (/tmp es world-writable)
- `-N ""` — passphrase vacia para uso no interactivo

**Certificate signing:**
```bash
ssh-keygen -s /opt/principal/ssh/ca -I "pwn-root" -n root -V +1h /tmp/pwn.pub
```
- `-s` — CA private key para firmar
- `-I` — etiqueta de identidad del certificado (solo para audit log, sin impacto de seguridad)
- `-n root` — el principal (como quien autentica este certificado)
- `-V +1h` — ventana de validez. Omitirlo crea un certificado inmediatamente expirado en OpenSSH moderno. `always:forever` crea un certificado permanente.

### Por que se firma la public key y no la private key?
Tienen roles distintos:
- **Public key** es firmada por la CA → produce el certificado → prueba autorizacion
- **Private key** se usa al momento del login → firma el challenge de sshd → prueba ownership

Ambas son necesarias. Un certificado sin la private key no puede responder al challenge de sshd. Una private key sin un certificado valido no sera confiada por un servidor configurado con CA.

### El vencimiento del certificado ayuda con la limpieza forense?
No. El vencimiento hace el certificado inutilizable pero no lo borra. Un investigador todavia puede encontrar el archivo, leer su contenido con `ssh-keygen -L`, y correlacionarlo con los logs de auth de SSH que registran permanentemente el certificate ID, CA fingerprint, y timestamp. La limpieza requiere borrar los archivos y registrar que se generaron log entries.

Comparto por aca el script de exploit luego de desglosarlo completamente paso a paso y simplificarlo para su correcto entendimiento:

https://github.com/rjceledon/hacking-automation-scripts/blob/main/python/CVE-2026-29000.py

Tambien dejo mi usuario para dar respetos en HTB si encontraron esto util:

https://app.hackthebox.com/users/337909

Gracias y saludos!
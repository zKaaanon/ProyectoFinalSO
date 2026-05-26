# Proyecto Final — Sistemas Operativos 2026-2

**Autor:** Reyna Mendez Cristian Ignacio  
**Materia:** Sistemas Operativos  

---

## Introducción

Este proyecto analiza, reproduce y corrige la vulnerabilidad **CVE-2026-31431**, conocida como *Copy Fail*, un error lógico descubierto en el subsistema criptográfico del kernel de Linux. La vulnerabilidad fue documentada públicamente en 2026 por el equipo de investigación de Theori y afecta prácticamente a todas las distribuciones de Linux publicadas desde 2017.

El error reside en el componente `authencesn`, una plantilla de cifrado autenticado que combina un algoritmo de cifrado (como AES) con un código de autenticación de mensajes (HMAC). El problema ocurre cuando el kernel escribe datos descifrados directamente en la **caché de páginas** de un archivo antes de verificar si esos datos son legítimos. Si la verificación falla, el kernel devuelve un error al programa que lo solicitó, pero la escritura en memoria ya ocurrió y no es revertida.

El resultado es que un usuario local sin ningún privilegio especial puede sobrescribir 4 bytes de cualquier archivo legible en el sistema directamente en memoria, sin que el archivo en disco sea modificado y sin que las herramientas de integridad tradicionales lo detecten. Con esto es posible corromper la caché de un binario *setuid* (como `/usr/bin/su`) y obtener acceso root.

El entorno de reproducción fue configurado en **GitHub Codespaces** compilando la versión vulnerable del kernel (Linux 6.6.86) y ejecutándola dentro de una máquina virtual con QEMU. La distribución elegida para las pruebas es **Debian 12 (Bookworm)** como sistema raíz de la VM, por su amplia documentación y disponibilidad de herramientas de depuración.

---

## Objetivos

1. **Identificar en código fuente** la línea exacta donde ocurre el error de escritura prematura dentro del archivo `crypto/algif_aead.c` del kernel Linux 6.6.86.
2. **Configurar un entorno reproducible**: Una vulnerable (v6.6.86), compiladas desde código fuente en GitHub Codespaces.
3. **Reproducir la vulnerabilidad** en el entorno vulnerable, capturando evidencia del comportamiento del sistema antes y después de la corrupción de la caché de páginas.
4. **Evaluar el impacto** de la vulnerabilidad sobre la integridad, confidencialidad y disponibilidad del sistema, y documentar sus limitaciones de detección ante herramientas convencionales.

---

## Marco Teórico

### La caché de páginas (*Page Cache*)

Cuando un programa abre un archivo y lee su contenido, el sistema operativo no accede al disco en cada operación de lectura, porque el disco es extremadamente lento comparado con la memoria RAM. En cambio, el kernel mantiene una zona de memoria llamada **caché de páginas** (*page cache*), donde guarda copias de los bloques del disco que se han leído recientemente.

La unidad mínima de esta caché es una **página de memoria**, que en la arquitectura x86-64 tiene un tamaño estándar de 4 096 bytes. Cada página representa un fragmento del contenido de un archivo almacenado en RAM. Cuando un proceso lee un archivo, en realidad está leyendo desde esta caché; si la página no está en memoria todavía, el kernel la carga desde disco (esto se llama *page fault* o fallo de página).

```text
Archivo en disco:   [bloque 0][bloque 1][bloque 2]...
                          ↓ se carga en RAM cuando se accede
Page cache en RAM:  [página 0][página 1][página 2]...
                          ↑ lo que realmente lee el proceso
```

### El bit sucio (*Dirty Bit*)

Cuando un proceso modifica el contenido de una página en la caché, el kernel necesita saber que esa página ya no es igual al bloque que hay en disco. Para esto existe el **dirty bit** (bit sucio): una bandera asociada a cada página que se activa cuando la página ha sido modificada pero aún no se ha escrito de vuelta al disco.

El proceso de sincronización funciona así:

1. Se carga una página del disco a la caché de páginas.
2. Un proceso escribe en esa página → el kernel activa el *dirty bit*.
3. Periódicamente (o cuando el proceso llama a `fsync()`), el kernel detecta las páginas sucias y las escribe de vuelta al disco.
4. Una vez escritas, el *dirty bit* se desactiva.

```text
Página en caché:  [datos]  dirty=0  → idéntica al disco
                      ↓ proceso escribe
Página en caché:  [datos modificados]  dirty=1  → pendiente de escribir
                      ↓ kernel sincroniza
Página en caché:  [datos modificados]  dirty=0  → ya actualizada en disco
```

Herramientas como `sha256sum` o `md5sum` leen el archivo a través de la caché de páginas. Sin embargo, herramientas de verificación de integridad como **AIDE** o **Tripwire** comparan checksums calculados contra hashes almacenados previamente. Si el archivo en disco no cambió pero la caché fue modificada sin activar el *dirty bit*, dichas herramientas reportarán que el archivo está intacto, aunque lo que el sistema ejecute sea la versión corrupta en memoria.

### Cifrado autenticado y HMAC

El kernel de Linux expone su subsistema criptográfico a los programas de usuario mediante la interfaz **AF_ALG** (*Algorithm sockets*). Esto permite que los procesos usen algoritmos de cifrado implementados en el kernel sin necesidad de tener privilegios especiales.

El algoritmo involucrado en esta vulnerabilidad es **authencesn**, que implementa **cifrado autenticado**: combina un cifrador de bloques (en este caso AES-CBC) con un código de autenticación HMAC-SHA256. La idea del cifrado autenticado es garantizar que los datos descifrados no hayan sido manipulados: primero se verifica la firma HMAC y sólo si es válida se entregan los datos descifrados.

```text
Flujo correcto de descifrado autenticado:
  datos cifrados → [verificar HMAC] → ¿válido? → [descifrar] → datos en claro

Flujo con el bug:
  datos cifrados → [descifrar y ESCRIBIR en caché] → [verificar HMAC] → falla → error
                                ↑
                    la escritura ya ocurrió y no se revierte
```

### La llamada `splice()` y la escritura sin copia

La llamada al sistema `splice()` permite mover datos entre dos descriptores de archivo sin copiarlos por espacio de usuario: el kernel los transfiere directamente en memoria usando las mismas páginas físicas. Esto es muy eficiente porque evita copias innecesarias.

Sin embargo, esta eficiencia introduce un problema cuando el origen o destino es la caché de páginas de un archivo: el kernel puede operar **directamente sobre las páginas del archivo** en lugar de sobre un buffer temporal. Cuando el resultado del descifrado se escribe de vuelta usando `splice()`, el kernel escribe en la página del archivo en caché, sin activar el *dirty bit* porque la operación proviene de una ruta de código criptográfico que no pasa por el mecanismo normal de escritura de archivos.

### Binarios *setuid* y escalada de privilegios

En Linux, los archivos ejecutables pueden tener el bit **setuid** activado. Cuando un proceso ejecuta un binario con ese bit, el sistema operativo eleva temporalmente los privilegios del proceso al nivel del propietario del binario. El ejemplo más común es `/usr/bin/su`, que pertenece a `root` y tiene el bit setuid activado: al ejecutarlo, el proceso corre con UID 0 aunque lo haya iniciado un usuario normal.

Si un atacante puede sobrescribir aunque sea 4 bytes de la caché de páginas de `/usr/bin/su`, puede modificar una instrucción del programa en memoria para que el binario ejecute código arbitrario con privilegios de root, sin que el archivo en disco cambie ni una sola letra.

---

## Desarrollo

### Identificación del error en código fuente

El error se encuentra en el archivo `crypto/algif_aead.c` del kernel de Linux, específicamente alrededor de la **línea 282**, en la función que maneja las operaciones de descifrado cuando los datos provienen de un *splice* de la caché de páginas.

```c
/* crypto/algif_aead.c — fragmento simplificado, línea ~282 */
static int algif_aead_recvmsg(struct socket *sock, struct msghdr *msg,
                               size_t ignored_len, int flags)
{
    /* ... */
    err = crypto_aead_decrypt(req);   /* (1) descifra y escribe en destino */
    
    if (err == -EBADMSG)              /* (2) verifica resultado HMAC */
        goto free;
    /* ... */
}
```

El problema está en el orden de operaciones:

1. `crypto_aead_decrypt()` escribe el resultado descifrado directamente en las páginas del *scatter-gather list* de destino.
2. Solo después se evalúa si el HMAC era válido (`-EBADMSG`).
3. Si el HMAC falló, la función retorna el error, pero no revierte la escritura.

---

## Resultados

| Prueba | Kernel vulnerable (6.6.86) | Kernel parcheado |
|---|---|---|
| PoC ejecutado como usuario sin privilegios | PAGE CACHE CORROMPIDO | Operación rechazada |
| Archivo en disco tras el PoC | Sin cambios | Sin cambios |
| `sha256sum /usr/bin/su` | Igual al original | Igual al original |
| Lectura del archivo tras el PoC | Bytes modificados | Bytes originales |

---

## Conclusiones

CVE-2026-31431 demuestra cómo un error de orden de operaciones en el subsistema criptográfico del kernel puede comprometer gravemente la seguridad del sistema.

La vulnerabilidad es especialmente peligrosa porque:

1. No requiere privilegios.
2. Es invisible para herramientas tradicionales de integridad.
3. Permite modificar binarios ejecutados directamente desde memoria.

La solución consiste en evitar escribir directamente sobre páginas del *page cache* antes de validar completamente el HMAC.

---

## Referencias

- Xint. (2026). *Copy Fail in Linux distributions*.
- Theori. (2026). *Copy Fail CVE-2026-31431*.
- Linux Kernel. (2024). *crypto/algif_aead.c*.
- Bovet, D. P., & Cesati, M. (2005). *Understanding the Linux Kernel*.

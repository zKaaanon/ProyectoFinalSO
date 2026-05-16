# Proyecto Final - Sistemas Operativos 2026-2

## Introducción
Copy Fail (CVE-2026-31431) es un bug lógico en la plantilla criptográfica *authencesn* del kernel de Linux.  
Permite que un usuario local sin privilegios dispare una escritura controlada y determinista de 4 bytes en la caché de páginas de cualquier archivo legible en el sistema.  
Con un simple script de Python de 732 bytes se puede modificar un binario *setuid* y obtener acceso root en prácticamente todas las distribuciones de Linux enviadas desde 2017.

El kernel nunca marca la página corrupta como *dirty* para escritura en disco, por lo que el archivo en disco permanece sin cambios y las comparaciones de checksum tradicionales no detectan la modificación.  
Sin embargo, la caché de páginas es lo que realmente se lee al acceder al archivo, por lo que la versión corrupta en memoria es inmediatamente visible en todo el sistema.  
Un usuario local sin privilegios puede aprovechar esto para obtener root corrompiendo la caché de páginas de un binario *setuid*.

## Objetivos
- Analizar, reproducir en entorno controlado y corregir la vulnerabilidad CVE-2026-31431 (Copy Fail) en el kernel de Linux, documentando técnicamente el proceso completo desde la detección del bug hasta la verificación del parche, como ejercicio práctico de estudio de un sistema operativo de código abierto.  
- Configurar un entorno de pruebas reproducible en máquina virtual con dos instancias de kernel: una vulnerable y una parcheada, documentando el proceso de compilación e instalación.  
- Reproducir la vulnerabilidad en el entorno vulnerable, capturando evidencia del comportamiento del sistema antes y después de la corrupción del *page cache*.  
- Evaluar el impacto de la vulnerabilidad en términos de las propiedades de seguridad del sistema operativo: confidencialidad, integridad y disponibilidad, así como sus limitaciones de detección frente a herramientas de integridad convencionales.  

---

## Marco Teórico

---

## Desarrollo

---

## Resultados

---

## Conclusiones

---

## Fuentes de información
- Xint. (2026). *Copy Fail in Linux distributions*. Recuperado de https://xint.io/blog/copy-fail-linux-distributions  
- Theori. (2026). *Copy Fail CVE-2026-31431*. GitHub repository. Recuperado de https://github.com/theori-io/copy-fail-CVE-2026-31431  
- Theori. (2026). *Copy Fail demonstration*. YouTube. Recuperado de https://www.youtube.com/watch?v=cIM_wCS3axw  

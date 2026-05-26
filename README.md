# Proyecto Final — Sistemas Operativos 2026-2

**Autor:** Reyna Mendez Cristian Ignacio

---

## Requisitos

- Cuenta de GitHub con acceso a **GitHub Codespaces**
- Aproximadamente 10 GB de espacio libre en el Codespace (compilación del kernel)
- Aproximadamente 20 minutos para compilar

---

## Paso 1 — Clonar y abrir en Codespaces

```bash
git clone https://github.com/zKaaanon/ProyectoFinalSO.git
```

O directamente desde GitHub:

1. Entrar al repositorio
2. Presionar el botón verde **Code**
3. Ir a la pestaña **Codespaces**
4. Seleccionar **Create codespace on main**

---

## Paso 2 — Compilar el kernel vulnerable (6.6.86)

Desde la terminal del Codespace:

```bash
cd /workspaces/ProyectoFinalSO/linux-vulnerable

git remote add upstream https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

git fetch upstream v6.6.86

git checkout FETCH_HEAD

make olddefconfig

make bzImage -j$(nproc)
```

Al finalizar la compilación deberá aparecer el siguiente mensaje:

```text
Kernel: arch/x86/boot/bzImage is ready
```

---

## Paso 3 — Arrancar la máquina virtual vulnerable

```bash
cd /workspaces/ProyectoFinalSO

./boot-vulnerable.sh
```

### Credenciales

| Usuario | Contraseña |
|----------|-------------|
| attacker | attacker |
| root     | root |

---

## Paso 4 — Montar el directorio compartido y ejecutar el PoC

```bash
su -c "mount -t 9p -o trans=virtio host0 /mnt/shared" root

python3 /mnt/shared/poc.py
```

---

## Resultado esperado

```text
[*] uid actual : 1000
[*] splice(file->pipe) : 32 bytes
[*] splice(pipe->AEAD) : 32 bytes
[*] Error esperado (HMAC inválido): Bad message
[!] La escritura ocurrió ANTES de que fallara el HMAC
```

---

## Estructura del proyecto

```text
ProyectoFinalSO/
├── boot-vulnerable.sh      # Script para arrancar la VM con QEMU
├── shared/
│   └── poc.py              # Proof of Concept del CVE
├── linux-vulnerable/       # Fuentes del kernel (checkout a v6.6.86)
└── Reporte.md              # Análisis técnico completo
```

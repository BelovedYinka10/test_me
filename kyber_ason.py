import ctypes
import os
import cycles  # Your custom rdtsc module

# ========== Kyber Setup ==========
KYBER_MODE = "512"
MODES = {
    "512": (800, 1632, 768, 32, "libkyber512_universal.dylib"),
    "768": (1184, 2400, 1088, 32, "libkyber768_universal.dylib"),
    "1024": (1568, 3168, 1568, 32, "libkyber1024.dylib"),
}
PK_LEN, SK_LEN, CT_LEN, SS_LEN, kyber_libname = MODES[KYBER_MODE]
kyber = ctypes.CDLL(os.path.abspath(kyber_libname))

Uint8Array = ctypes.POINTER(ctypes.c_ubyte)
ULongPtr = ctypes.POINTER(ctypes.c_ulonglong)

# Kyber functions
kyber.keypair.argtypes = [Uint8Array, Uint8Array]
kyber.encapsulate.argtypes = [Uint8Array, Uint8Array, Uint8Array]
kyber.decapsulate.argtypes = [Uint8Array, Uint8Array, Uint8Array]

# Kyber buffers
pk = (ctypes.c_ubyte * PK_LEN)()
sk = (ctypes.c_ubyte * SK_LEN)()
ct = (ctypes.c_ubyte * CT_LEN)()
ss1 = (ctypes.c_ubyte * SS_LEN)()
ss2 = (ctypes.c_ubyte * SS_LEN)()

print("Initial CPU Cycle Counter:", cycles.rdtsc())

# Kyber: Keypair
start = cycles.rdtsc()
kyber.keypair(pk, sk)
end = cycles.rdtsc()
print(f"[Cycles] Kyber Keypair: {end - start}")

# Kyber: Encapsulation
start = cycles.rdtsc()
kyber.encapsulate(pk, ct, ss1)
end = cycles.rdtsc()
print(f"[Cycles] Kyber Encapsulation: {end - start}")

# Kyber: Decapsulation
start = cycles.rdtsc()
kyber.decapsulate(ct, sk, ss2)
end = cycles.rdtsc()
print(f"[Cycles] Kyber Decapsulation: {end - start}")
print(f"Kyber{KYBER_MODE} Shared Secret Match:", bytes(ss1) == bytes(ss2))

# ========== Ascon Setup ==========
ascon = ctypes.CDLL(os.path.abspath("./libascon.dylib"))
ascon.crypto_aead_encrypt.argtypes = [Uint8Array, ULongPtr, Uint8Array, ctypes.c_ulonglong,
                                      Uint8Array, ctypes.c_ulonglong,
                                      Uint8Array, Uint8Array, Uint8Array]
ascon.crypto_aead_encrypt.restype = ctypes.c_int

ascon.crypto_aead_decrypt.argtypes = [Uint8Array, ULongPtr, Uint8Array, Uint8Array, ctypes.c_ulonglong,
                                      Uint8Array, ctypes.c_ulonglong, Uint8Array, Uint8Array]
ascon.crypto_aead_decrypt.restype = ctypes.c_int

# ========== Encrypt 600KB Message with Ascon Using Kyber Key ==========
# msg = os.urandom(600 * 1024)
msg = os.urandom(880 * 1024)  # Simulate 880 KB payload

msg_len = len(msg)
ad = b""
nonce = b"\x01" * 16
key = bytes(ss1[:16])  # Use first 16 bytes of Kyber shared secret

# Convert buffers
msg_buf = (ctypes.c_ubyte * msg_len).from_buffer_copy(msg)
ad_buf = (ctypes.c_ubyte * len(ad))(*ad) if ad else None
key_buf = (ctypes.c_ubyte * 16).from_buffer_copy(key)
nonce_buf = (ctypes.c_ubyte * 16).from_buffer_copy(nonce)
cipher_len = ctypes.c_ulonglong(msg_len + 16)
cipher_buf = (ctypes.c_ubyte * cipher_len.value)()

# Ascon Encryption
start = cycles.rdtsc()
ascon.crypto_aead_encrypt(cipher_buf, ctypes.byref(cipher_len),
                          msg_buf, msg_len,
                          ad_buf, len(ad) if ad else 0,
                          None, nonce_buf, key_buf)
end = cycles.rdtsc()
print(f"[Cycles] Ascon Encryption (600KB): {end - start}")

# Ascon Decryption
msg_out_buf = (ctypes.c_ubyte * msg_len)()
msg_out_len = ctypes.c_ulonglong(0)

start = cycles.rdtsc()
ascon.crypto_aead_decrypt(msg_out_buf, ctypes.byref(msg_out_len),
                          None, cipher_buf, cipher_len.value,
                          ad_buf, len(ad) if ad else 0,
                          nonce_buf, key_buf)
end = cycles.rdtsc()
print(f"[Cycles] Ascon Decryption (600KB): {end - start}")

# Final check
decrypted = bytes(msg_out_buf[:msg_out_len.value])
print("Ascon Decryption Match:", decrypted == msg)

import ctypes
import os
import cycles  # Your custom rdtsc module

print("Initial CPU Cycle Counter:", cycles.rdtsc())

### === SELECT KYBER SECURITY LEVEL HERE === ###
KYBER_MODE = "512"  # Options: "512", "768", "1024"
### ========================================= ###

# Configuration map
MODES = {
    "512": (800, 1632, 768, 32, "libkyber512_universal.dylib"),
    "768": (1184, 2400, 1088, 32, "libkyber768_universal.dylib"),
    "1024": (1568, 3168, 1568, 32, "libkyber1024.dylib"),
}

print("Mode:", KYBER_MODE)

# Get selected mode parameters
if KYBER_MODE not in MODES:
    raise ValueError("Invalid KYBER_MODE. Use '512', '768', or '1024'.")

PK_LEN, SK_LEN, CT_LEN, SS_LEN, libname = MODES[KYBER_MODE]

# Load the appropriate shared library
lib = ctypes.CDLL(os.path.abspath(libname))

# Define ctypes pointer type
Uint8Array = ctypes.POINTER(ctypes.c_ubyte)

# Set function signatures
lib.keypair.argtypes = [Uint8Array, Uint8Array]
lib.keypair.restype = None

lib.encapsulate.argtypes = [Uint8Array, Uint8Array, Uint8Array]
lib.encapsulate.restype = None

lib.decapsulate.argtypes = [Uint8Array, Uint8Array, Uint8Array]
lib.decapsulate.restype = None

# Allocate buffers
pk = (ctypes.c_ubyte * PK_LEN)()
sk = (ctypes.c_ubyte * SK_LEN)()
ct = (ctypes.c_ubyte * CT_LEN)()
ss1 = (ctypes.c_ubyte * SS_LEN)()
ss2 = (ctypes.c_ubyte * SS_LEN)()

# --- Keypair Timing ---
start_cycles = cycles.rdtsc()
lib.keypair(pk, sk)
end_cycles = cycles.rdtsc()
print(f"[Cycles] Keypair: {end_cycles - start_cycles} cycles")

# --- Encapsulation Timing ---
start_cycles = cycles.rdtsc()
lib.encapsulate(pk, ct, ss1)
end_cycles = cycles.rdtsc()
print(f"[Cycles] Encapsulation: {end_cycles - start_cycles} cycles")

# --- Decapsulation Timing ---
start_cycles = cycles.rdtsc()
lib.decapsulate(ct, sk, ss2)
end_cycles = cycles.rdtsc()
print(f"[Cycles] Decapsulation: {end_cycles - start_cycles} cycles")

# Output results
print(f"\nKyber{KYBER_MODE}")
print("Shared Secret 1:", bytes(ss1).hex())
print("Shared Secret 2:", bytes(ss2).hex())
print("Match:", bytes(ss1) == bytes(ss2))

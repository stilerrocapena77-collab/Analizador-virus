import hashlib
import os

# --- Función para calcular el hash de un archivo ---
def calcular_hash(ruta_archivo):
    sha256 = hashlib.sha256()
    with open(ruta_archivo, "rb") as archivo:
        while chunk := archivo.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# --- Lista básica de hashes conocidos como malware (ejemplo) ---
hashes_maliciosos = [
    "44d88612fea8a8f36de82e1278abb02f",  # Ejemplo tipo EICAR
    "5d41402abc4b2a76b9719d911017c592"   # Otro ejemplo
]

# --- Función para analizar archivos ---
def analizar_archivo(ruta_archivo):
    if not os.path.exists(ruta_archivo):
        return f"❌ Archivo no encontrado: {ruta_archivo}"

    hash_archivo = calcular_hash(ruta_archivo)
    print(f"🧾 Hash calculado: {hash_archivo}")

    if hash_archivo in hashes_maliciosos:
        return "⚠️ Este archivo coincide con un virus conocido."
    else:
        return "✅ El archivo es seguro (no coincide con virus conocidos)."

# --- Ejecución principal ---
if __name__ == "__main__":
    ruta = input("Ingresa la ruta del archivo a analizar: ")
    resultado = analizar_archivo(ruta)
    print(resultado)

# -*- coding: utf-8 -*-
"""
Implementación del algoritmo RC5 (modos ECB y CBC)
"""
import secrets
from bitarray import bitarray

#Parámetros
W = 32                  #Tamaño de la palabra en bits
R = 12                  #Número de rondas

U = W // 8              #Bytes por palabra
T = 2 * (R + 1)         #Número de subclaves
MASCARA = (1 << W) - 1  

def entero_a_bits(n):
    """
    Convierte un entero en un bitarray de longitud W
    input: n (entero)
    output: bitarray de longitud W
    """
    bits = bitarray(endian='big')
    bits.frombytes((n & MASCARA).to_bytes(4, 'big'))
    return bits

def bits_a_entero(bits):
    """
    Convierte un bitarray en un entero
    input: bits (bitarray)
    output: entero
    """
    return int.from_bytes(bits.tobytes(), 'big')

def rotar_izquierda(bits, n):
    """
    Rota un bitarray a la izquierda n posiciones
    input: bits (bitarray), n (entero)
    output: bitarray
    """
    n %= len(bits)

    if n == 0:
        return bits.copy()

    return bits[n:] + bits[:n]

def rotar_derecha(bits, n):
    """
        
    input: bits (bitarray), n (entero)
    output: bitarray
    """
    n %= len(bits)

    if n == 0:
        return bits.copy()

    return  bits[-n:] + bits[:-n]

def sumar_modular(a, b):
    """
    Realiza una suma modular de dos bitarrays
    input: a (bitarray), b (bitarray)
    output: bitarray
    """
    resultado = (bits_a_entero(a) + bits_a_entero(b)) & MASCARA
    return entero_a_bits(resultado)

def inicializar_S():
    """
    Inicializa la tabla de subclaves S
    input: Ninguno
    output: Lista de bitarrays
    """
    P = 0xB7E15163
    Q = 0x9E3779B9

    S = [entero_a_bits(0) for _ in range(T)]
    S[0] = entero_a_bits(P)

    for i in range(1, T):
        S[i] = sumar_modular(S[i - 1], entero_a_bits(Q))

    return S

def preparar_L(clave):
    """
    Convertir la clave en palabras para crear L
    input: clave (bytes)
    output: Lista de bitarrays
    """
    c = (len(clave) + U - 1) // U
    L = [0] * c

    # Agrupación little-endian según RC5
    for i in range(len(clave) - 1, -1, -1):
        L[i // U] = (
            (L[i // U] << 8) + clave[i]
        ) & MASCARA

    return [entero_a_bits(x) for x in L]

def mezclar_tablas(S, L):
    """
    Mezclar las tablas S y L
    input: S (lista de bitarrays), L (lista de bitarrays)
    output: S (lista de bitarrays)
    """
    A = entero_a_bits(0)
    B_aux = entero_a_bits(0)

    i = 0
    j = 0

    iteraciones = 3 * max(T, len(L))

    for _ in range(iteraciones):
        # A = S[i] = ROTL(S[i] + A + B, 3)
        suma = (
            bits_a_entero(S[i])
            + bits_a_entero(A)
            + bits_a_entero(B_aux)
        ) & MASCARA

        A = rotar_izquierda(entero_a_bits(suma), 3)
        S[i] = A.copy()

        # B = L[j] = ROTL(L[j] + A + B, A + B)
        suma = (
            bits_a_entero(L[j])
            + bits_a_entero(A)
            + bits_a_entero(B_aux)
        ) & MASCARA

        desplazamiento = (
            bits_a_entero(A) + bits_a_entero(B_aux)
        ) & MASCARA

        B_aux = rotar_izquierda(
            entero_a_bits(suma), desplazamiento
        )
        L[j] = B_aux.copy()

        i = (i + 1) % T
        j = (j + 1) % len(L)

    return S

def expandir_clave(clave):
    """
    Expandir clave
    input: clave (bytes)
    output: Lista de bitarrays
    """
    S = inicializar_S()
    L = preparar_L(clave)
    
    return mezclar_tablas(S, L)

def cifrar_bloque(bloque, S):
    """
    Cifra un bloque de 8 bytes usando las subclaves S
    input: bloque (bytes), S (lista de bitarrays)
    output: bytes
    """
    if len(bloque) != 8:
        raise ValueError("El bloque debe tener 8 bytes")

    # Dividir el bloque en dos palabras de 32 bits
    A = int.from_bytes(bloque[:4], "little")
    B_bloque = int.from_bytes(bloque[4:], "little")

    # Sumar las dos primeras subclaves
    A = (A + bits_a_entero(S[0])) & MASCARA
    B_bloque = (B_bloque + bits_a_entero(S[1])) & MASCARA

    # Ejecutar las rondas de RC5
    for i in range(1, R + 1):
        A = rotar_izquierda(
            entero_a_bits(A ^ B_bloque),
            B_bloque
        )
        A = (
            bits_a_entero(A) + bits_a_entero(S[2 * i])
        ) & MASCARA

        B_bloque = rotar_izquierda(
            entero_a_bits(B_bloque ^ A),
            A
        )
        B_bloque = (
            bits_a_entero(B_bloque)
            + bits_a_entero(S[2 * i + 1])
        ) & MASCARA

    # Reconstruir el bloque cifrado
    return (
        A.to_bytes(4, "little")
        + B_bloque.to_bytes(4, "little")
    )


def xor_bytes(a, b):
    """
    XOR byte a byte de dos secuencias de la misma longitud
    input: a (bytes), b (bytes)
    output: bytes
    """
    return bytes(x ^ y for x, y in zip(a, b))

def aplicar_relleno(datos):
    """
    Añade relleno PKCS#7 para bloques de 8 bytes
    input: datos (bytes)
    output: bytes con longitud múltiplo de 8
    """
    relleno = 8 - (len(datos) % 8)
    return datos + bytes([relleno]) * relleno

def quitar_relleno(datos):
    """
    Elimina y valida el relleno PKCS#7
    input: datos (bytes)
    output: bytes sin relleno
    """
    if len(datos) == 0:
        raise ValueError("No hay datos que descifrar")

    relleno = datos[-1]
    # Todos los bytes de relleno deben valer lo mismo (no solo el último)
    if relleno < 1 or relleno > 8 or datos[-relleno:] != bytes([relleno]) * relleno:
        raise ValueError("Relleno inválido (¿clave o modo incorrectos?)")

    return datos[:-relleno]

def cifrar_mensaje(mensaje, clave, modo="ECB"):
    """
    Cifra un mensaje usando RC5 con la clave proporcionada
    input: mensaje (str), clave (bytes), modo (str: "ECB" o "CBC")
    output: cifrado (bytes). En CBC, los 8 primeros bytes son el IV
    """
    datos = aplicar_relleno(mensaje.encode("utf-8"))

    # Generar las subclaves
    S = expandir_clave(clave)

    if modo == "ECB":
        # Cada bloque se cifra de forma independiente
        cifrado = b""
        for i in range(0, len(datos), 8):
            cifrado += cifrar_bloque(datos[i:i + 8], S)
        return cifrado

    elif modo == "CBC":
        # IV aleatorio e impredecible, nuevo en cada cifrado.
        # Se usa 'secrets' (CSPRNG) y no 'random', que es predecible.
        iv = secrets.token_bytes(8)

        cifrado = iv           # El IV no es secreto: se envía delante
        anterior = iv          # C_0 = IV
        for i in range(0, len(datos), 8):
            # C_i = E_K(P_i XOR C_{i-1})
            bloque = xor_bytes(datos[i:i + 8], anterior)
            anterior = cifrar_bloque(bloque, S)
            cifrado += anterior
        return cifrado

    else:
        raise ValueError("Modo no válido. Usa 'ECB' o 'CBC'")

def descifrar_bloque(bloque, S):
    """
    Descifra un bloque de 8 bytes usando las subclaves S
    input: bloque (bytes), S (lista de bitarrays)
    output: bytes
    """
    if len(bloque) != 8:
        raise ValueError("El bloque debe tener 8 bytes")

    # Dividir el bloque en dos palabras de 32 bits
    A = int.from_bytes(bloque[:4], "little")
    B_bloque = int.from_bytes(bloque[4:], "little")

    # Ejecutar las rondas de RC5 en orden inverso
    for i in range(R, 0, -1):
    # Deshacer: B = ROTL(B ^ A, A) + S[2i+1]
        B_bloque = (B_bloque - bits_a_entero(S[2 * i + 1])) & MASCARA   # 1. restar subclave
        B_bloque = bits_a_entero(
            rotar_derecha(entero_a_bits(B_bloque), A)                   # 2. rotar a la derecha
        ) ^ A                                                           # 3. XOR con A

        # Deshacer: A = ROTL(A ^ B, B) + S[2i]
        A = (A - bits_a_entero(S[2 * i])) & MASCARA
        A = bits_a_entero(
            rotar_derecha(entero_a_bits(A), B_bloque)
        ) ^ B_bloque

    # Restar las dos primeras subclaves
    B_bloque = (B_bloque - bits_a_entero(S[1])) & MASCARA
    A = (A - bits_a_entero(S[0])) & MASCARA

    # Reconstruir el bloque descifrado
    return (
        A.to_bytes(4, "little")
        + B_bloque.to_bytes(4, "little")
    )

def descifrar_mensaje(cifrado, clave, modo="ECB"):
    """
    Descifra un mensaje cifrado usando RC5 con la clave proporcionada
    input: cifrado (bytes), clave (bytes), modo (str: "ECB" o "CBC")
    output: mensaje (str)
    """
    if len(cifrado) == 0 or len(cifrado) % 8 != 0:
        raise ValueError("El cifrado debe tener una longitud múltiplo de 8 bytes")

    # Generar las subclaves
    S = expandir_clave(clave)

    datos = b""

    if modo == "ECB":
        for i in range(0, len(cifrado), 8):
            datos += descifrar_bloque(cifrado[i:i + 8], S)

    elif modo == "CBC":
        if len(cifrado) < 16:
            raise ValueError("En CBC el cifrado necesita IV + al menos un bloque")

        # Separar el IV (primer bloque) del resto
        anterior = cifrado[:8]
        for i in range(8, len(cifrado), 8):
            bloque = cifrado[i:i + 8]
            # P_i = D_K(C_i) XOR C_{i-1}
            datos += xor_bytes(descifrar_bloque(bloque, S), anterior)
            anterior = bloque

    else:
        raise ValueError("Modo no válido. Usa 'ECB' o 'CBC'")

    try:
        return quitar_relleno(datos).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("No se pudo decodificar el mensaje (¿clave o modo incorrectos?)")

def convertir_clave(clave, formato):
    """
    Transforma la clave según el formato escogido
    input: clave (str), formato (str)
    output: clave (bytes)
    """
    if formato == "texto":
        clave = clave.encode("utf-8")

    elif formato == "hex":
        try:
            clave = bytes.fromhex(clave)
        except ValueError:
            raise ValueError("La clave hexadecimal no es válida")

    else:
        raise ValueError("Formato no válido. Usa 'texto' o 'hex'")

    return clave

def pedir_modo():
    """
    Pide al usuario el modo de operación
    input: Ninguno
    output: modo (str: "ECB" o "CBC")
    """
    while True:
        print("Modo de operación:")
        print("  1) ECB (cada bloque por separado)")
        print("  2) CBC (bloques encadenados con IV)")
        opcion = input("Elija el modo: ").strip()
        if opcion == "1":
            return "ECB"
        if opcion == "2":
            return "CBC"
        print("Modo no válido. Por favor, ingrese 1 o 2.")

def main():
    """
    Función principal para ejecutar el cifrado y descifrado
    """
    continuar = True
    while continuar:
        print("RC5 - Cifrado y Descifrado de Mensajes")
        print("--------------------------------------")
        print("1) Cifrar un mensaje")
        print("2) Descifrar un mensaje")
        print("0) Salir")
        print("--------------------------------------")
        opcion = input("Ingrese la opción deseada: ").strip()

        try: 
            if opcion == "1":
                mensaje = input("Ingrese el mensaje a cifrar: ")
                clave = input("Ingrese la clave (texto): ")
                while len(clave) < 3 or len(clave) > 256:
                    print("La clave debe tener al menos 3 caracteres y máximo 256 caracteres.")
                    clave = input("Ingrese la clave (texto): ")

                modo = pedir_modo()
                clave_bytes = convertir_clave(clave, "texto")
                cifrado = cifrar_mensaje(mensaje, clave_bytes, modo)

                print("Mensaje original:", mensaje)
                print(f"Mensaje cifrado en {modo} (hex):", cifrado.hex())
                if modo == "CBC":
                    print("(Los primeros 16 caracteres hex son el IV)")
                print("\n")

            elif opcion == "2":
                cifrado_hex = input("Ingrese el mensaje cifrado en hexadecimal: ")

                clave = input("Ingrese la clave (texto): ")
                while len(clave) < 3 or len(clave) > 256:
                    print("La clave debe tener al menos 3 caracteres y máximo 256 caracteres.")
                    clave = input("Ingrese la clave (texto): ")

                modo = pedir_modo()
                cifrado_bytes = bytes.fromhex(cifrado_hex)
                clave_bytes = convertir_clave(clave, "texto")
                descifrado = descifrar_mensaje(cifrado_bytes, clave_bytes, modo)

                print("Mensaje descifrado:", descifrado)
                print("\n")

            elif opcion == "0":
                print("Saliendo del programa.")
                continuar = False

            else:
                print("Opción no válida. Por favor, ingrese 1, 2 o 0.")
        except ValueError as e:
            print("Error:", e)

if __name__ == "__main__":
    main()
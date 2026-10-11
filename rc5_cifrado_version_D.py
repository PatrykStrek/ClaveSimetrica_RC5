# -*- coding: utf-8 -*-
"""
Created on Sun Oct 11 17:31:26 2026

@author: diego
"""
from bitarray import bitarray

#Parámetros
W = 32                  #Tamaño de la palabra en bits
R = 12                  #Número de rondas
B = 16                  #Longitud de la clave en bytes

U = W // 8              #Bytes por palabra
T = 2 * (R + 1)         #Número de subclaves
MASCARA = (1 << W) - 1  




"""
Operaciones con bits
"""
def entero_a_bits(n):
    bits = bitarray(endian='big')
    bits.frombytes((n & MASCARA).to_bytes(4, 'big'))
    return bits


def bits_a_entero(bits):
    return int.from_bytes(bits.tobytes(), 'big')


"""
Rotación de bits a la izquierda
"""
def rotar_izquierda(bits, n):
    n %= len(bits)

    if n == 0:
        return bits.copy()

    return bits[n:] + bits[:n]


"""
Rotación de bits a la derecha
"""
def rotar_derecha(bits, n):
    n %= len(bits)

    if n == 0:
        return bits.copy()

    return  bits[-n:] + bits[:-n]


"""
Suma modular
"""
def sumar_modular(a, b):
    resultado = (bits_a_entero(a) + bits_a_entero(b)) & MASCARA
    return entero_a_bits(resultado)


"""
Inicializar la tabla S
"""
def inicializar_S():
    P = 0xB7E15163
    Q = 0x9E3779B9

    S = [entero_a_bits(0) for _ in range(T)]
    S[0] = entero_a_bits(P)

    for i in range(1, T):
        S[i] = sumar_modular(S[i - 1], entero_a_bits(Q))

    return S

"""
Convertir la clave en palabras para crear L
"""
def preparar_L(clave):
    if len(clave) != B:
        raise ValueError("La clave debe tener 16 bytes")

    c = (len(clave) + U - 1) // U
    L = [0] * c

    # Agrupación little-endian según RC5
    for i in range(len(clave) - 1, -1, -1):
        L[i // U] = (
            (L[i // U] << 8) + clave[i]
        ) & MASCARA

    return [entero_a_bits(x) for x in L]


"""
Mezclar las tablas S y L
"""
def mezclar_tablas(S, L):
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


"""
Expandir clave
"""
def expandir_clave(clave):
    S = inicializar_S()
    L = preparar_L(clave)
    
    return mezclar_tablas(S, L)


"""
Cifrar mensaje
"""
def cifrar_bloque(bloque, S):
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


def cifrar_mensaje(mensaje, clave):
    datos = mensaje.encode("utf-8")

    # Relleno PKCS#7 para bloques de 8 bytes
    relleno = 8 - (len(datos) % 8)
    datos += bytes([relleno]) * relleno

    # Generar las subclaves
    S = expandir_clave(clave)

    cifrado = b""

    # Cifrar bloque por bloque
    for i in range(0, len(datos), 8):
        bloque = datos[i:i + 8]
        cifrado += cifrar_bloque(bloque, S)

    return cifrado



mensaje = "hola mundo"

# Clave de 16 bytes (128 bits)
clave = bytes.fromhex(
    "00112233445566778899AABBCCDDEEFF"
)

cifrado = cifrar_mensaje(mensaje, clave)

print("Mensaje original:", mensaje)
print("Mensaje cifrado (hex):", cifrado.hex())
print("Longitud del cifrado:", len(cifrado), "bytes")



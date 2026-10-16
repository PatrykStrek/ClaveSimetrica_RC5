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
        raise ValueError('La clave debe tener ', B, ' bytes')

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


"""
Transforma la clave según el formato escogido
"""
def convertir_clave(clave, formato):
    if formato == "texto":
        clave = clave.encode("utf-8")

    elif formato == "hex":
        try:
            clave = bytes.fromhex(clave)
        except ValueError:
            raise ValueError("La clave hexadecimal no es válida")

    else:
        raise ValueError("Formato no válido. Usa 'texto' o 'hex'")

    if len(clave) != B:
        raise ValueError(f"La clave debe tener exactamente {B} bytes")

    return clave




mensaje = "help Wednesday finish?” She dashed out of the room with her feet slapping against the\
floorboards and Wednesday again, resisted the urge to roll her eyes. Part of her understood\
the urge to reach out to someone who wasn’t present – she did that constantly. But she could\
also see how much Josie just wanted to celebrate her partner, and Emiliana wasn’t quite\
letting her.\
Still, Josie didn’t look offended as she took off, merely pulled herself up to the stools at the\
counter. “I’m assuming you don’t need, or want help?” Shaking her head, Wednesday stared\
at the contents of the pot, hoping her eyes wouldn’t water in betrayal as Josie tried to pull\
feelings out of her. “Was class any better today?”\
Giving a dismissive shrug, Wednesday replied with a snide, “I wasn’t called to the dean’s\
office, if that’s what you’re wondering.”\
“That isn’t what I was wondering, but that’s…good. A low bar, but – glad you crossed it. It\
seems like you decidedly do not want to talk about school? Is there anything you do want to\
talk about?”\
“There is nothing I could bring up that wouldn’t end with a lecture or therapy session. I’d lie\
and tell you I’m fine, but you won’t believe it. I’m just going to be quiet.”\
There was a distinctive beat of Josie’s short nails on the marble of the counter and a few\
moments passed as she clearly selected her next words carefully before offering, “Do you\
want to hear about snakes?”\
“Not entirely.”\
“Do you want to talk about Enid?”\
“Josie.” Wednesday ended her attempts with a gaze flickered up through long lashes that she\
hoped read frustration.\
“Fine. Do you want to take a bowl to go and be miserable in your own condo?”\
“No.”\
“Wednesday…”\
She turned around and crossed her arms, letting out a long huff, avoiding looking at her\
former mentor-turned-big-sister. “Alright. I’m going to hug you now. Incoming.”\
Melting into Josie’s hold, Wednesday let it go on until Emiliana skipped back into the room,\
her footfalls always sounding so heavy for someone so light. She squeezed Josie and\
Wednesday to her, pecking the tops of both of their heads. “Bien-aimée, I apologize for being\
so short with you when you came home. I am still learning to filter the distractions while\
reading."

clave = convertir_clave(
    "waifus1234567890",
    "texto"
)

cifrado = cifrar_mensaje(mensaje, clave)

print("Mensaje original:", mensaje)
print("Mensaje cifrado (hex):", cifrado.hex())

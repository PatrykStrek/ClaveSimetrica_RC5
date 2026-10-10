# =============================================================================
# rc5_primitivas.py  --  PERSONA 1
# RC5-w/r/b con bitarray: parámetros globales, conversiones y operaciones básicas
# =============================================================================
#
# ORDEN DE TRABAJO (Persona 1)
#   Este fichero es la BASE: los otros dos importan de aquí, así que va primero.
#   1º  int_a_palabra, palabra_a_int        (todo lo demás las usa)
#   2º  bytes_a_palabra, palabra_a_bytes    (las necesitan Persona 2 y 3)
#   3º  sumar, restar
#   4º  rotar_izquierda, rotar_derecha
#   5º  probar_primitivas
#   En cuanto termines los pasos 1º y 2º, avisa: desbloquean a los demás.
#
# CONVENIO DE REPRESENTACIÓN (acordadlo los tres ANTES de programar)
#   - Una "palabra" es un bitarray de exactamente W bits.
#   - Índice 0 = bit MÁS significativo (endian='big' de bitarray). Así una
#     rotación a la izquierda es mover los primeros bits al final.
#   - El orden little-endian que pide el artículo de Rivest se aplica SOLO al
#     empaquetar bytes en palabras (bytes_a_palabra / palabra_a_bytes), no al
#     orden interno de los bits de la palabra.
#   - Ninguna función modifica sus argumentos: siempre devuelve un bitarray nuevo.
# =============================================================================

from bitarray import bitarray
from bitarray.util import int2ba, ba2int


# ----------------------------- Variables globales ----------------------------

W = 32                    # Tamaño de palabra en bits (valores permitidos: 16, 32, 64)
R = 12                    # Número de rondas
B = 16                    # Longitud de la clave secreta en bytes (0..255)

U = W // 8                # Bytes por palabra
T = 2 * (R + 1)           # Número de palabras de la tabla de clave expandida S
C = max(1, -(-B // U))    # Número de palabras de L = max(1, ceil(B / U))
BLOQUE_BYTES = 2 * U      # Tamaño del bloque en bytes (dos palabras: A y B)

MODULO = 2 ** W           # Todas las sumas y restas son módulo 2^W

# Constantes mágicas para W = 32 (sección 4.3 del artículo). Están como enteros:
# se convierten a palabra con int_a_palabra() cuando hagan falta.
# OJO: si cambiáis W hay que cambiarlas (P16/Q16 o P64/Q64 del artículo).
P_W = 0xB7E15163          # Odd((e - 2) * 2^W)
Q_W = 0x9E3779B9          # Odd((phi - 1) * 2^W)

ENDIAN_BITS = "big"       # Orden de bits dentro de cada bitarray (ver convenio)


# ------------------------------- Conversiones --------------------------------

def int_a_palabra(n: int) -> bitarray:
    """
    Input:  n -> entero no negativo.
    Output: bitarray de exactamente W bits (endian ENDIAN_BITS) que representa n.

    Qué hace por dentro:
      - Reduce n módulo 2^W (por si llega un valor mayor).
      - Lo convierte a bitarray de longitud fija W, rellenando con ceros a la
        izquierda (mirad los parámetros de int2ba para longitud y endian).
    """


def palabra_a_int(palabra: bitarray) -> int:
    """
    Input:  palabra -> bitarray de W bits.
    Output: entero sin signo en el rango [0, 2^W - 1].

    Qué hace por dentro:
      - Comprueba que la longitud es W (si no, error: delata fallos de otros
        módulos muy pronto).
      - Convierte el bitarray a entero SIN signo (ba2int).
    """


def bytes_a_palabra(datos: bytes) -> bitarray:
    """
    Input:  datos -> exactamente U bytes.
    Output: palabra (bitarray de W bits).

    Qué hace por dentro:
      - Comprueba que len(datos) == U.
      - Interpreta los bytes en LITTLE-ENDIAN, como pide el artículo: el primer
        byte ocupa las posiciones de menor peso de la palabra y el último las
        de mayor peso.
      - Devuelve el resultado como palabra con el convenio del fichero.
    Ejemplo de control (W = 32): los bytes 21 A5 DB EE son la palabra 0xEEDBA521.
    """


def palabra_a_bytes(palabra: bitarray) -> bytes:
    """
    Input:  palabra -> bitarray de W bits.
    Output: U bytes en little-endian (byte de menor peso primero).

    Qué hace por dentro:
      - Es la inversa exacta de bytes_a_palabra.
      - Debe cumplirse: palabra_a_bytes(bytes_a_palabra(x)) == x para todo x.
    """


# ---------------------- Operaciones primitivas de RC5 ------------------------
# El XOR no necesita función: bitarray ya lo hace con el operador ^ entre dos
# bitarrays de la misma longitud. Las tres operaciones de RC5 son suma, XOR y
# rotación (más sus inversas).

def sumar(a: bitarray, b: bitarray) -> bitarray:
    """
    Input:  a, b -> palabras de W bits.
    Output: palabra de W bits con (a + b) mod 2^W.

    Qué hace por dentro:
      - bitarray no tiene aritmética: pasa a entero, suma, reduce módulo 2^W
        (descartando el acarreo final) y vuelve a palabra.
    """


def restar(a: bitarray, b: bitarray) -> bitarray:
    """
    Input:  a, b -> palabras de W bits.
    Output: palabra de W bits con (a - b) mod 2^W.

    Qué hace por dentro:
      - Inversa de sumar. El resultado nunca puede ser negativo: hay que
        reducir módulo 2^W (complemento a dos).
      - Debe cumplirse: restar(sumar(a, b), b) == a.
    """


def rotar_izquierda(x: bitarray, y: bitarray) -> bitarray:
    """
    Input:  x -> palabra a rotar.
            y -> palabra que indica CUÁNTO rotar (rotación dependiente de datos).
    Output: palabra x rotada cíclicamente a la izquierda.

    Qué hace por dentro:
      - Calcula el desplazamiento como (valor de y) mod W: solo cuentan los
        lg(W) bits de menor peso de y.
      - Rotación CÍCLICA: los bits que salen por la izquierda entran por la
        derecha (no es un desplazamiento << normal, que los perdería).
      - Caso límite: desplazamiento 0 devuelve una copia de x.
    """


def rotar_derecha(x: bitarray, y: bitarray) -> bitarray:
    """
    Input:  x -> palabra a rotar.
            y -> palabra que indica cuánto rotar.
    Output: palabra x rotada cíclicamente a la derecha (y mod W) posiciones.

    Qué hace por dentro:
      - Inversa de rotar_izquierda (solo se usa al descifrar).
      - Debe cumplirse: rotar_derecha(rotar_izquierda(x, y), y) == x.
    """


# --------------------------------- Pruebas -----------------------------------

def probar_primitivas() -> None:
    """
    Input:  nada.
    Output: nada (lanza AssertionError si algo falla).

    Qué hace por dentro:
      - Comprueba ida y vuelta de las conversiones (int <-> palabra, bytes <-> palabra).
      - Comprueba el ejemplo de control de bytes_a_palabra.
      - Comprueba el desbordamiento de sumar (valor máximo + 1 = 0) y de restar (0 - 1).
      - Comprueba que cada rotación se deshace con su inversa, y los casos de
        desplazamiento 0, W y mayor que W.
    """

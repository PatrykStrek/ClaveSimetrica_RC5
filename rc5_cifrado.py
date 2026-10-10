# =============================================================================
# rc5_cifrado.py  --  PERSONA 3
# RC5-w/r/b con bitarray: cifrado/descifrado de bloque e interfaz texto <-> hex
# =============================================================================
#
# ORDEN DE TRABAJO (Persona 3)
#   1º  aplicar_padding, quitar_padding   (solo usan bytes: no dependen de nadie,
#                                          hazlas mientras Persona 1 empieza)
#   2º  cifrar_bloque, descifrar_bloque   (necesitan las primitivas de Persona 1;
#                                          se pueden probar con una S inventada:
#                                          descifrar(cifrar(x)) == x)
#   3º  texto_a_bloques, bloques_a_texto  (necesitan bytes_a_palabra / palabra_a_bytes)
#   4º  bloques_a_hex, hex_a_bloques
#   5º  cifrar, descifrar                 (necesitan expandir_clave de Persona 2)
#   6º  probar_vectores_articulo          (prueba final de los tres juntos)
#
# AVISOS DE SEGURIDAD
#   - Cifrar bloque a bloque de forma independiente es el modo ECB: dos bloques
#     de texto claro iguales dan el mismo bloque cifrado, así que se filtran
#     patrones del mensaje. Vale para la práctica; no para uso real.
#   - No hay autenticación: quien modifique el criptograma no será detectado.
#   - RC5-32/12/16 es solo académico (12 rondas están rotas por criptoanálisis
#     diferencial y el bloque de 64 bits es pequeño).
# =============================================================================

from bitarray import bitarray
from bitarray.util import ba2hex, hex2ba

from rc5_primitivas import (
    W, R, U, T, BLOQUE_BYTES,
    bytes_a_palabra, palabra_a_bytes,
    sumar, restar, rotar_izquierda, rotar_derecha,
)
from rc5_clave import expandir_clave


# ----------------------------- Variables globales ----------------------------

CODIFICACION_TEXTO = "utf-8"   # Codificación del texto claro

# Vectores de prueba del apéndice del artículo (RC5-32/12/16): (clave, claro, cifrado).
# Están en hexadecimal como SECUENCIA DE BYTES, tal cual los imprime el artículo
# (byte de menor peso de cada palabra primero). Cotejadlos con vuestro PDF.
# Son bloques sueltos, SIN padding: se prueban con cifrar_bloque, no con cifrar().
VECTORES_PRUEBA = [
    ("00000000000000000000000000000000", "0000000000000000", "21A5DBEE154B8F6D"),
    ("915F4619BE41B2516355A50110A9CE91", "21A5DBEE154B8F6D", "F7C013AC5B2B8952"),
    ("783348E75AEB0F2FD7B169BB8DC16787", "F7C013AC5B2B8952", "2F42B3B70369FC92"),
]


# --------------------------- Cifrado de un bloque ----------------------------

def cifrar_bloque(A: bitarray, B: bitarray, S: list[bitarray]) -> tuple[bitarray, bitarray]:
    """
    Input:  A, B -> las dos palabras (W bits) del bloque de texto claro.
            S    -> clave expandida (T palabras).
    Output: tupla (A, B) con las dos palabras del bloque cifrado.

    Qué hace por dentro (sección 4.1 del artículo):
      - Blanqueo inicial: suma S[0] a A y S[1] a B.
      - Repite para i de 1 a R (ambos incluidos):
          * A = ((A XOR B) rotado a la izquierda B posiciones) + S[2i]
          * B = ((B XOR A) rotado a la izquierda A posiciones) + S[2i + 1],
            usando el A NUEVO de la línea anterior.
      - No modifica los argumentos de entrada.
    """


def descifrar_bloque(A: bitarray, B: bitarray, S: list[bitarray]) -> tuple[bitarray, bitarray]:
    """
    Input:  A, B -> las dos palabras del bloque cifrado.
            S    -> la misma clave expandida usada al cifrar.
    Output: tupla (A, B) con las dos palabras del texto claro.

    Qué hace por dentro (sección 4.2 del artículo):
      - Deshace cifrar_bloque paso a paso y en orden INVERSO: i de R hasta 1,
        primero B y luego A.
      - Cada paso: resta la subclave, rota a la DERECHA y hace el XOR.
      - Al final resta S[1] a B y S[0] a A.
    Control: descifrar_bloque(*cifrar_bloque(A, B, S), S) == (A, B).
    """


# -------------------------------- Padding ------------------------------------

def aplicar_padding(datos: bytes) -> bytes:
    """
    Input:  datos -> bytes de cualquier longitud (incluida 0).
    Output: bytes cuya longitud es múltiplo de BLOQUE_BYTES.

    Qué hace por dentro (PKCS#7):
      - Calcula cuántos bytes n faltan para completar el bloque (entre 1 y
        BLOQUE_BYTES).
      - Añade n bytes, todos con valor n.
      - Si los datos ya son múltiplo del bloque, añade un bloque ENTERO de
        relleno (si no, al quitarlo sería ambiguo).
    """


def quitar_padding(datos: bytes) -> bytes:
    """
    Input:  datos -> bytes con padding PKCS#7 (longitud múltiplo de BLOQUE_BYTES).
    Output: los bytes originales sin el relleno.

    Qué hace por dentro:
      - Lee el último byte: indica cuántos bytes de relleno hay.
      - Valida que ese valor está entre 1 y BLOQUE_BYTES y que TODOS los bytes
        de relleno valen lo mismo.
      - Si no es válido lanza ValueError (suele significar clave incorrecta o
        criptograma dañado).
    """


# ------------------------ Conversiones texto / hex ---------------------------

def texto_a_bloques(texto: str) -> list[tuple[bitarray, bitarray]]:
    """
    Input:  texto -> mensaje en claro (str).
    Output: lista de bloques; cada bloque es una tupla (A, B) de palabras.

    Qué hace por dentro:
      - Codifica el texto a bytes con CODIFICACION_TEXTO.
      - Le aplica el padding.
      - Trocea en grupos de BLOQUE_BYTES: los primeros U bytes de cada grupo
        forman A y los U siguientes forman B (con bytes_a_palabra).
    """


def bloques_a_texto(bloques: list[tuple[bitarray, bitarray]]) -> str:
    """
    Input:  bloques -> lista de tuplas (A, B) ya DESCIFRADAS.
    Output: el mensaje original (str).

    Qué hace por dentro:
      - Convierte cada palabra a bytes (palabra_a_bytes) y concatena todo en
        el mismo orden: A y luego B de cada bloque.
      - Quita el padding.
      - Decodifica los bytes con CODIFICACION_TEXTO.
    """


def bloques_a_hex(bloques: list[tuple[bitarray, bitarray]]) -> str:
    """
    Input:  bloques -> lista de tuplas (A, B) ya CIFRADAS.
    Output: cadena hexadecimal con el criptograma (2 caracteres por byte).

    Qué hace por dentro:
      - Pasa cada palabra a bytes en little-endian y concatena.
      - Convierte los bytes a hexadecimal. Decidid mayúsculas o minúsculas y
        mantenedlo siempre igual.
    Control: el bloque cifrado del primer vector de prueba debe salir
    exactamente como "21A5DBEE154B8F6D" (si sale "EEDBA5216D8F4B15" es que
    falta el paso little-endian).
    """


def hex_a_bloques(hexadecimal: str) -> list[tuple[bitarray, bitarray]]:
    """
    Input:  hexadecimal -> criptograma como cadena hexadecimal.
    Output: lista de bloques (A, B) listos para descifrar.

    Qué hace por dentro:
      - Limpia espacios y saltos de línea; acepta mayúsculas y minúsculas.
      - Valida que solo hay caracteres hexadecimales y que la longitud en bytes
        es múltiplo de BLOQUE_BYTES (si no, ValueError).
      - Pasa a bytes y trocea en palabras igual que texto_a_bloques (sin padding).
    """


# ---------------------------- Interfaz pública -------------------------------

def cifrar(texto: str, clave) -> str:
    """
    Input:  texto -> mensaje en claro (str).
            clave -> clave secreta (str o bytes, de B bytes).
    Output: criptograma en hexadecimal (str).

    Qué hace por dentro:
      - Expande la clave UNA sola vez (expandir_clave), no una vez por bloque.
      - texto_a_bloques -> cifrar_bloque sobre cada bloque -> bloques_a_hex.
    """


def descifrar(hexadecimal: str, clave) -> str:
    """
    Input:  hexadecimal -> criptograma en hexadecimal (str).
            clave       -> la misma clave usada al cifrar.
    Output: mensaje en claro (str).

    Qué hace por dentro:
      - Expande la clave una sola vez.
      - hex_a_bloques -> descifrar_bloque sobre cada bloque -> bloques_a_texto.
      - Con clave incorrecta lo normal es que falle el padding o la
        decodificación: captura el error y da un mensaje genérico, sin volcar
        datos intermedios.
    Control: descifrar(cifrar(m, k), k) == m, también con tildes, con mensaje
    vacío y con mensajes de longitud múltiplo exacto del bloque.
    """


# --------------------------------- Pruebas -----------------------------------

def probar_vectores_articulo() -> None:
    """
    Input:  nada (usa VECTORES_PRUEBA).
    Output: nada (lanza AssertionError indicando qué vector falla).

    Qué hace por dentro:
      - Para cada vector: pasa clave, claro y cifrado de hexadecimal a bytes.
      - Expande la clave, parte el claro en (A, B) y llama a cifrar_bloque
        DIRECTAMENTE (sin padding).
      - Compara el resultado con el cifrado esperado y comprueba además que
        descifrar_bloque devuelve el claro.
    Si falla el primer vector (clave todo ceros): el fallo suele estar en
    mezclar_clave o en el orden de bytes, no en las rondas.
    """

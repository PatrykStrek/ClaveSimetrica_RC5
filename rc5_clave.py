# =============================================================================
# rc5_clave.py  --  PERSONA 2
# RC5-w/r/b con bitarray: expansión de la clave (sección 4.3 del artículo)
# =============================================================================
#
# ORDEN DE TRABAJO (Persona 2)
#   1º  validar_clave      (no depende de nadie: hazla mientras Persona 1 empieza)
#   2º  inicializar_S      (solo necesita int_a_palabra y sumar)
#   3º  clave_a_palabras   (necesita bytes_a_palabra de Persona 1)
#   4º  mezclar_clave      (necesita sumar y rotar_izquierda; es la más delicada)
#   5º  expandir_clave     (une todo lo anterior)
#   6º  probar_expansion
#   Persona 3 necesita expandir_clave para las pruebas finales con los vectores
#   del artículo, así que es la entrega que más prisa corre.
#
# AVISOS DE SEGURIDAD
#   - S y L son material secreto: quien tenga S puede descifrar sin conocer K.
#     Los print de depuración de S o de la clave se quitan en la versión final.
#   - No escribáis la clave real dentro del código ni la subáis al repositorio.
# =============================================================================

from bitarray import bitarray

from rc5_primitivas import (
    W, B, U, T, C, P_W, Q_W,
    int_a_palabra, palabra_a_int, bytes_a_palabra,
    sumar, rotar_izquierda,
)


# ----------------------------- Variables globales ----------------------------

CODIFICACION_CLAVE = "utf-8"   # Cómo se pasa a bytes una clave dada como texto
PASADAS_MEZCLA = 3             # Nº de pasadas sobre el mayor de los arrays S y L
ROTACION_FIJA = 3              # Rotación fija que se aplica a S[i] en la mezcla


# ------------------------------- Funciones -----------------------------------

def validar_clave(clave) -> bytes:
    """
    Input:  clave -> str o bytes con la clave secreta del usuario.
    Output: la clave como bytes, de longitud exactamente B.

    Qué hace por dentro:
      - Si llega como str, la codifica a bytes con CODIFICACION_CLAVE.
      - Comprueba que la longitud en BYTES es B (ojo: en UTF-8 una letra con
        tilde o una ñ ocupan 2 bytes, no 1).
      - Si la longitud no coincide, lanza ValueError.
    Seguridad: no rellenar con ceros ni truncar en silencio. Una clave rellenada
    con ceros es más débil de lo que el usuario cree; es mejor rechazarla.
    """


def clave_a_palabras(K: bytes) -> list[bitarray]:
    """
    Input:  K -> clave secreta de B bytes (ya validada).
    Output: lista L con C palabras (bitarray de W bits cada una).

    Qué hace por dentro (paso 1 de la expansión):
      - Trocea K en grupos de U bytes consecutivos.
      - Cada grupo se convierte en una palabra en little-endian (bytes_a_palabra).
      - Si el último grupo queda incompleto, las posiciones que faltan se
        rellenan con bytes a cero.
      - Caso especial del artículo: si B == 0, L tiene una única palabra a cero.
    """


def inicializar_S() -> list[bitarray]:
    """
    Input:  nada (usa las globales T, P_W y Q_W).
    Output: lista S con T palabras, todavía INDEPENDIENTE de la clave.

    Qué hace por dentro (paso 2 de la expansión):
      - S[0] es la constante P_W convertida a palabra.
      - Cada S[i] siguiente es S[i-1] + Q_W (suma módulo 2^W): una progresión
        aritmética.
    Control: dos ejecuciones dan siempre el mismo resultado, y len(S) == T.
    """


def mezclar_clave(S: list[bitarray], L: list[bitarray]) -> list[bitarray]:
    """
    Input:  S -> tabla inicializada (T palabras).
            L -> clave en palabras (C palabras).
    Output: tabla S definitiva (T palabras), ya dependiente de la clave.

    Qué hace por dentro (paso 3 de la expansión):
      - Parte de dos índices i, j a cero y dos palabras acumuladoras A, B a cero.
      - Repite PASADAS_MEZCLA * max(T, C) veces:
          * Nuevo S[i] = (S[i] + A + B) rotado a la izquierda ROTACION_FIJA
            posiciones. Ese valor es también el nuevo A.
          * Nuevo L[j] = (L[j] + A + B) rotado a la izquierda (A + B) posiciones,
            usando el A recién calculado. Ese valor es también el nuevo B.
          * i avanza módulo T; j avanza módulo C.
      - Trabaja sobre COPIAS de S y L para no modificar los argumentos.
    Errores típicos:
      - rotar_izquierda espera una palabra como cantidad: el 3 fijo hay que
        convertirlo a palabra.
      - Usar el A antiguo en vez del nuevo al calcular B.
      - Dar solo T vueltas en vez de 3 * max(T, C).
    """


def expandir_clave(clave) -> list[bitarray]:
    """
    Input:  clave -> str o bytes con la clave secreta.
    Output: tabla S de T palabras lista para cifrar y descifrar.

    Qué hace por dentro:
      - Encadena los pasos: validar_clave -> clave_a_palabras -> inicializar_S
        -> mezclar_clave.
      - Es la ÚNICA función de este fichero que debe llamar Persona 3.
    """


# --------------------------------- Pruebas -----------------------------------

def probar_expansion() -> None:
    """
    Input:  nada.
    Output: nada (lanza AssertionError si algo falla).

    Qué hace por dentro:
      - Comprueba que validar_clave rechaza claves de longitud distinta de B.
      - Comprueba que L tiene C palabras y S tiene T palabras de W bits.
      - Comprueba que inicializar_S empieza en P_W y que S[1] - S[0] es Q_W.
      - Comprueba que la misma clave da siempre la misma S, y que cambiar un
        solo byte de la clave cambia S.
      - La prueba definitiva (valores exactos) se hace con Persona 3, usando
        los vectores del apéndice del artículo.
    """

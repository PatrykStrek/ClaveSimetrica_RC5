"""
Implementación del algoritmo RC5 (modos ECB y CBC)
"""
import secrets
import tkinter as tk
from bitarray import bitarray
from tkinter import ttk, messagebox

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
    Rota un bitarray a la derecha n posiciones
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
    Añade relleno para bloques de 8 bytes
    input: datos (bytes)
    output: bytes con longitud múltiplo de 8
    """
    relleno = 8 - (len(datos) % 8)
    return datos + bytes([relleno]) * relleno

def quitar_relleno(datos):
    """
    Elimina y valida el relleno
    input: datos (bytes)
    output: bytes sin relleno
    """
    if len(datos) == 0:
        raise ValueError("No hay datos que descifrar")

    relleno = datos[-1]
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

    S = expandir_clave(clave)

    if modo == "ECB":
        cifrado = b""
        for i in range(0, len(datos), 8):
            cifrado += cifrar_bloque(datos[i:i + 8], S)
        return cifrado

    elif modo == "CBC":
        iv = secrets.token_bytes(8)

        cifrado = iv
        anterior = iv
        for i in range(0, len(datos), 8):
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
        B_bloque = (B_bloque - bits_a_entero(S[2 * i + 1])) & MASCARA
        B_bloque = bits_a_entero(
            rotar_derecha(entero_a_bits(B_bloque), A)
        ) ^ A

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

        anterior = cifrado[:8]
        for i in range(8, len(cifrado), 8):
            bloque = cifrado[i:i + 8]
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

"""
Interfaz gráfica (Tkinter) para el cifrado RC5 en modos ECB y CBC.
"""

class AppRC5:
    """Ventana principal de la aplicación."""

    def __init__(self, raiz):
        """
        Inicializa la interfaz gráfica.
        input: raiz (tk.Tk)
        """
        self.raiz = raiz
        self.raiz.title("RC5 - Cifrado y Descifrado")
        self.raiz.minsize(560, 480)

        # Variables ligadas a los widgets
        self.modo = tk.StringVar(value="CBC")
        self.mostrar_clave = tk.BooleanVar(value=False)

        self._crear_widgets()

    def _crear_widgets(self):
        """
        Construye la interfaz gráfica.
        input: self (AppRC5)
        output: None
        """
        marco = ttk.Frame(self.raiz, padding=12)
        marco.pack(fill="both", expand=True)
        marco.columnconfigure(0, weight=1)

        # Entrada: texto en claro o cifrado en hexadecimal
        ttk.Label(marco, text="Entrada (texto a cifrar o cifrado en hex):").grid(
            row=0, column=0, sticky="w")
        self.txt_entrada = tk.Text(marco, height=6, wrap="word")
        self.txt_entrada.grid(row=1, column=0, sticky="nsew", pady=(2, 10))

        # Clave (oculta por defecto)
        fila_clave = ttk.Frame(marco)
        fila_clave.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        fila_clave.columnconfigure(1, weight=1)
        ttk.Label(fila_clave, text="Clave:").grid(row=0, column=0, padx=(0, 6))
        self.ent_clave = ttk.Entry(fila_clave, show="•")
        self.ent_clave.grid(row=0, column=1, sticky="ew")
        ttk.Checkbutton(fila_clave, text="Mostrar", variable=self.mostrar_clave,
                        command=self._alternar_clave).grid(row=0, column=2, padx=(6, 0))

        # Selección de modo
        fila_modo = ttk.LabelFrame(marco, text="Modo de operación", padding=6)
        fila_modo.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        ttk.Radiobutton(fila_modo, text="ECB (bloques independientes)",
                        variable=self.modo, value="ECB").pack(side="left", padx=6)
        ttk.Radiobutton(fila_modo, text="CBC (encadenado con IV)",
                        variable=self.modo, value="CBC").pack(side="left", padx=6)

        # Botones de acción
        fila_botones = ttk.Frame(marco)
        fila_botones.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(fila_botones, text="Cifrar", command=self.cifrar).pack(side="left")
        ttk.Button(fila_botones, text="Descifrar", command=self.descifrar).pack(side="left", padx=6)
        ttk.Button(fila_botones, text="Copiar resultado", command=self.copiar).pack(side="left")

        # Salida (solo lectura)
        ttk.Label(marco, text="Resultado:").grid(row=5, column=0, sticky="w")
        self.txt_salida = tk.Text(marco, height=6, wrap="word", state="disabled")
        self.txt_salida.grid(row=6, column=0, sticky="nsew", pady=(2, 6))

        # Línea de estado (p. ej. aviso del IV)
        self.lbl_estado = ttk.Label(marco, text="", foreground="gray")
        self.lbl_estado.grid(row=7, column=0, sticky="w")

        # Las cajas de texto crecen al redimensionar la ventana
        marco.rowconfigure(1, weight=1)
        marco.rowconfigure(6, weight=1)

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------
    def _alternar_clave(self):
        """
        Alterna la visibilidad de la clave en el Entry.
        input: self (AppRC5)
        output: None
        """
        self.ent_clave.config(show="" if self.mostrar_clave.get() else "•")

    def _leer_clave(self):
        """
        Lee la clave del Entry y la valida.
        input: self (AppRC5)
        output: clave (bytes)
        """
        clave = self.ent_clave.get()
        if len(clave) < 3 or len(clave) > 256:
            raise ValueError("La clave debe tener entre 3 y 256 caracteres.")
        return convertir_clave(clave, "texto")

    def _leer_entrada(self):
        """
        Lee el contenido del Text de entrada.
        input: self (AppRC5)
        output: texto (str)
        """
        return self.txt_entrada.get("1.0", "end-1c")

    def _escribir_salida(self, texto, estado=""):
        """
        Escribe el resultado en el Text de salida y actualiza la línea de estado.
        input: self (AppRC5), texto (str), estado (str)
        output: None
        """
        self.txt_salida.config(state="normal")
        self.txt_salida.delete("1.0", "end")
        self.txt_salida.insert("1.0", texto)
        self.txt_salida.config(state="disabled")
        self.lbl_estado.config(text=estado)

    # ------------------------------------------------------------------
    # Acciones de los botones (callbacks)
    # ------------------------------------------------------------------
    def cifrar(self):
        """
        Cifra el mensaje de entrada con la clave y el modo seleccionados.
        input: self (AppRC5)
        output: None
        """
        try:
            clave = self._leer_clave()
            modo = self.modo.get()
            cifrado = cifrar_mensaje(self._leer_entrada(), clave, modo)
            aviso = "Los primeros 16 caracteres hex son el IV." if modo == "CBC" else ""
            self._escribir_salida(cifrado.hex(), aviso)
        except ValueError as e:
            messagebox.showerror("Error al cifrar", str(e))

    def descifrar(self):
        """
        Descifra el mensaje de entrada con la clave y el modo seleccionados.
        input: self (AppRC5)
        output: None
        """
        try:
            clave = self._leer_clave()
            cifrado_hex = "".join(self._leer_entrada().split())
            try:
                cifrado = bytes.fromhex(cifrado_hex)
            except ValueError:
                raise ValueError("La entrada no es hexadecimal válido.")
            mensaje = descifrar_mensaje(cifrado, clave, self.modo.get())
            self._escribir_salida(mensaje)
        except ValueError as e:
            messagebox.showerror("Error al descifrar", str(e))

    def copiar(self):
        """
        Copia el resultado al portapapeles.
        input: self (AppRC5)
        output: None
        """
        resultado = self.txt_salida.get("1.0", "end-1c")
        if resultado:
            self.raiz.clipboard_clear()
            self.raiz.clipboard_append(resultado)
            self.lbl_estado.config(text="Resultado copiado al portapapeles.")

    def limpiar(self):
        """ 
        Limpia los campos de entrada y salida.
        input: self (AppRC5)
        output: None
        """
        self.txt_entrada.delete("1.0", "end")
        self.ent_clave.delete(0, "end")
        self._escribir_salida("")


def main():
    """
    Función principal para ejecutar la aplicación.
    input: Ninguno
    output: None
    """
    raiz = tk.Tk()
    AppRC5(raiz)
    raiz.mainloop()


if __name__ == "__main__":
    main()
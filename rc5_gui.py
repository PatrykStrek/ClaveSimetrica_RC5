# -*- coding: utf-8 -*-
"""
Interfaz gráfica (Tkinter) para el cifrado RC5 en modos ECB y CBC.
La lógica criptográfica está en rc5.py; aquí solo hay presentación.
"""
import tkinter as tk
from tkinter import ttk, messagebox

# Reutilizamos las funciones ya probadas de rc5.py
from rc5_CBC import cifrar_mensaje, descifrar_mensaje, convertir_clave


class AppRC5:
    """Ventana principal de la aplicación."""

    def __init__(self, raiz):
        self.raiz = raiz
        self.raiz.title("RC5 - Cifrado y Descifrado")
        self.raiz.minsize(560, 480)

        # Variables ligadas a los widgets
        self.modo = tk.StringVar(value="CBC")
        self.mostrar_clave = tk.BooleanVar(value=False)

        self._crear_widgets()

    # ------------------------------------------------------------------
    # Construcción de la interfaz
    # ------------------------------------------------------------------
    def _crear_widgets(self):
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
        ttk.Button(fila_botones, text="Limpiar", command=self.limpiar).pack(side="right")

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
        self.ent_clave.config(show="" if self.mostrar_clave.get() else "•")

    def _leer_clave(self):
        """Valida la clave con las mismas reglas que la versión de consola."""
        clave = self.ent_clave.get()
        if len(clave) < 3 or len(clave) > 256:
            raise ValueError("La clave debe tener entre 3 y 256 caracteres.")
        return convertir_clave(clave, "texto")

    def _leer_entrada(self):
        # Text añade un '\n' final automáticamente: lo quitamos
        return self.txt_entrada.get("1.0", "end-1c")

    def _escribir_salida(self, texto, estado=""):
        self.txt_salida.config(state="normal")
        self.txt_salida.delete("1.0", "end")
        self.txt_salida.insert("1.0", texto)
        self.txt_salida.config(state="disabled")
        self.lbl_estado.config(text=estado)

    # ------------------------------------------------------------------
    # Acciones de los botones (callbacks)
    # ------------------------------------------------------------------
    def cifrar(self):
        try:
            clave = self._leer_clave()
            modo = self.modo.get()
            cifrado = cifrar_mensaje(self._leer_entrada(), clave, modo)
            aviso = "Los primeros 16 caracteres hex son el IV." if modo == "CBC" else ""
            self._escribir_salida(cifrado.hex(), aviso)
        except ValueError as e:
            messagebox.showerror("Error al cifrar", str(e))

    def descifrar(self):
        try:
            clave = self._leer_clave()
            # Quitamos espacios y saltos de línea que se cuelan al pegar
            cifrado_hex = "".join(self._leer_entrada().split())
            try:
                cifrado = bytes.fromhex(cifrado_hex)
            except ValueError:
                raise ValueError("La entrada no es hexadecimal válido.")
            mensaje = descifrar_mensaje(cifrado, clave, self.modo.get())
            self._escribir_salida(mensaje)
        except ValueError as e:
            # Para la práctica se muestra el motivo exacto; en un sistema real
            # convendría un mensaje genérico (ver ataque padding oracle)
            messagebox.showerror("Error al descifrar", str(e))

    def copiar(self):
        resultado = self.txt_salida.get("1.0", "end-1c")
        if resultado:
            self.raiz.clipboard_clear()
            self.raiz.clipboard_append(resultado)
            self.lbl_estado.config(text="Resultado copiado al portapapeles.")

    def limpiar(self):
        self.txt_entrada.delete("1.0", "end")
        self.ent_clave.delete(0, "end")
        self._escribir_salida("")


def main():
    raiz = tk.Tk()
    AppRC5(raiz)
    raiz.mainloop()   # Bucle de eventos: Tkinter espera clics y llama a los callbacks


if __name__ == "__main__":
    main()
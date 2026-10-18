# -*- coding: utf-8 -*-
"""
Created on Sun Oct 18 11:44:16 2026

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
        raise ValueError('La clave debe tener ', B,' bytes')

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
Descifrar bloque
"""
def descifrar_bloque(bloque, S):
    if len(bloque) != 8: 
        raise ValueError("El bloque debe tener 8 bytes")
    
    #Dividimos el bloque cifrado en 2 palabras
    A = int.from_bytes(bloque[:4], "little")
    B_bloque = int.from_bytes(bloque[4:], "little")
    
    #Recorremos las rondas en orden inverso
    for i in range(R, 0, -1):
        #Deshacer B
        B_bloque = (B_bloque - bits_a_entero(S[2 * i + 1])) & MASCARA 
        B_bloque = bits_a_entero(rotar_derecha(entero_a_bits(B_bloque), A)) ^ A
        
        #Deshacer A
        A = (A - bits_a_entero(S[2 * i])) & MASCARA
        A = bits_a_entero(rotar_derecha(entero_a_bits(A), B_bloque)) ^ B_bloque
        
    #Deshacer las sumas iniciales
    B_bloque = (B_bloque - bits_a_entero(S[1])) & MASCARA
    A = (A - bits_a_entero(S[0])) & MASCARA
    
    #Reconstruir el bloque original
    return(
        A.to_bytes(4, "little") + B_bloque.to_bytes(4, "little")
    )


"""
Descifrar mensaje
"""

def descifrar_mensaje(cifrado, clave):
    if len(cifrado) == 0 or len(cifrado) % 8 != 0:
        raise ValueError("El cifrado debe contener bloques completos")

    # Generar las mismas subclaves
    S = expandir_clave(clave)

    datos = b""

    # Descifrar bloque por bloque
    for i in range(0, len(cifrado), 8):
        bloque = cifrado[i:i + 8]
        datos += descifrar_bloque(bloque, S)

    # Eliminar el relleno PKCS#7
    relleno = datos[-1]

    if relleno < 1 or relleno > 8:
        raise ValueError("Relleno PKCS#7 no válido")

    if datos[-relleno:] != bytes([relleno]) * relleno:
        raise ValueError("Relleno PKCS#7 no válido")

    datos = datos[:-relleno]

    # Convertir los bytes recuperados en texto
    return datos.decode("utf-8")


"""
Convierta la cadena hexadecimal en bytes y descifre el mensaje
"""
def descifrar_hexadecimal(cifrado_hex, clave):
    # Eliminar espacios, tabulaciones y saltos de línea
    cifrado_hex = "".join(cifrado_hex.split())

    # Convertir el hexadecimal a bytes
    cifrado_bytes = bytes.fromhex(cifrado_hex)

    # Convertir la clave a bytes si está en texto plano
    if isinstance(clave, str):
        clave = clave.encode("utf-8")

    # Descifrar el mensaje
    return descifrar_mensaje(cifrado_bytes, clave)



cifrado = "e3ca43c3b5ae1ab1371000eed6f3531caf6a4ea7ad8cfc2a9a528faaa75783a27ea67010df495619e38d3\
    c8983a66e3c904149509314611a483553f98d6563f5d6d81cf9a9cb2d64aa2bca67e4ec140178aee5ccee21a7f55\
    fcecc5ece5cfa7e7b44e6b41e156080a2231b3f782749e1efff281419ec4aafafcb5faa08b6bea690bcd0b945e8d\
    3879ba25a566c2751a63020a3b3a4084e3fd0e8eb26b2edbe70532dec6757813a2f79903bb9acb7f0dd481777151\
    335c4ba7e29afaf256b8a3d59df47179f068e1b0cd5c15e2e4b2aa4b83e6e3d2297cad98ba60bb13875a6d28f966\
    ffe8e1264d9fa01494f0e930bb099b8dd9852dc0dc612a5b2fdbf84ab67b28d2ebca65855be2434ec23f0b8a5524\
    5e3fd7b44b5d785c9e13c905c3220a4d73bf2f362e5de13a50387bfd7e0ab59e8a82c7b6b17d314a76bea907d02b\
    35b9312b0ff20120533ef2f482283a915501046d5d49c4f59b436a5763ff75e215c0abd97326beff7b1595fb59aa\
    8ea4de91ade9e7153d3e00cd6bf9eb07370df0c89f89f0f2f4d1a67ee0b8c1695b74662990c9809510403dc09e8b\
    4999261c04617e6a5e2a92a08ad0939e175b4792a2ca80357a28cf1db61fec98ff4cdc10e1bea702efcec4dc64c9\
    6198ffefd68e816e8e3a8a81471091ea5181fd24e556625434d09a7c1118d90fa899e6caf4c1db7ab74d5ec444af\
    35af0ae5401203e2e89fc0fc16d33193775eb42066426e1b4a98df7bd798947d79e5f82e842224511f22f2620b77\
    b8d0d4a6b89760f2a5f5578d2120f02758f5ea01aaaa56a48efca66d8d01e69df866564e38d3c8983a66e3c8cc91\
    0e89125dcf7ace54886fbc2a7277ca10b762bf9ff46f291e28b7b62cbb04fc25fbe85a86feb8c02dce6553b06ec0\
    8bc2b26da319b09e174db83ca3ebe0afb9513e314c61a5e2e3b1015d0e5f2ae4ce76e919169c71c8b4f2a7b6aec8\
    70f41c73f5892258d7b28c56fa4a8cef26a27d2a6b2fbd98126d62ed1ae99643d56cdaee2f59a898321932cb18ee\
    5c13b2a52bcaf03168f2d446b89760f2a5f55781ea21b44cfe7d028f4aa5c85b24cc674b853f6c8623fcb5fe2b34\
    90202167c6b5f266649d37d2cf51f3ce99626d7d7e2121852846692e1ef618898df38f0dd687205df3ce9869eb10\
    45510ba4fbce1dacbbbcce3a9fb9b34f880bffd79f34cb5800328d45778cca7ffa09f59e786ae3866d57cab93aad\
    ddb7143eaac1e31c6238fbcafb8ea71220e800328d45778cca776f37439596fbf55000dd2234be1ffc6072ee1c7e\
    18ec5a680dccc73234ac2053d388c8f69cc406e9354129b388007fb7a2ce5ad607fe0b45cf815c3785880bb8540f\
    04efa60385181e595d7199fb5ee2d3d201fcc82cf1c98ddc86df2b55ccf3ac6fb2298473fcdb85ec5665da2fd550\
    b5c85dbe6c94245f135216a433a16cd11af6890c96ade6e491a7a0ccc6169698b27c50412dca4d420b80a8bd4e23\
    f76c00966ab6e78e9922af0a078407d579f4612d111b8e308a4519e00bdf679ab8049884657685266eafc58076ae\
    09474444de82ad0fa9ec4d3760ec322b2073fd9724bb2ea7b6d025d7530f984134155d2ee899ece7f1bce97a36a4\
    81546d6b344d881f95bbd924e87ad03de5d8df5eb7e44dc975b826db43aa1ae13087e27daff48ff2b09a93a23533\
    2789898e2cda99fd90629777f9be00d56e38705dc46391b52fa726fe8fbe4296be275167fbf315d407b897661aa5\
    bb27b673531c4ff5c93638e5349b2b024e1e9123b9f4e12e7287bd196e5660ccb18cdb84c1f1e7e89ae9924bdb05\
    54ef4ffcb3beff3713934b2e545e232be1088f394865d9d0562fe235cfa39ffbacb5941248780f96aee6b75701ef\
    f9c849ae57b0aadfde9113d1aafef0ecdc5c1bfdb9e469d47760cfca9297906ebc2ca311d324482c3c2fdf0c7b2d\
    9593f67c8f03f1c22d6d6f56dcd56477bec8dc713bcb5a6b2a1da70c97e146f54e0bdee9326df9d70077bd5d0187\
    06fada690b1b07b7e564c7344be43f5eba9691edfa6cbc38965dd99b3a1abed2be56d37f842c2a192580cc9a9230\
    2edb72e121c3b5dcb3c75da941311428b6dab23db528e19fc300c92a3da19f9d462b6f0a4612ba5c27eaae0b5cbc\
    5920caffc9282111363d311c881667a0dff12b88d29067040969ba5e3f6d9b9dab981693e87122491ceade089e45\
    b1bac8f6b5942b25aaf5fdb70c8c85813f240ac5b62b1252a81a5f2fa9f48e7102b7c2d36dd7b1a209f461213b3a\
    250a0b12cb2f796c37f7eb7920631b3200269e4f680c3d1dd1c82b7c4598bfd3a92e218f3f41c27cc68ce408bb46\
    26775e92fb36c181ab7c3c6d75ca243afc24ac2233452419bf62d57b2356b90b88886c2ddb4a54715c7084ae2e6b\
    03318260d3e0fee3d12d99dd62641cdf09e732b6724317793b0c4ba546e24e818aa44a051ffb6869ba780c3bc4ad\
    412455b18f8fb2f6104233acbba6fb383914bd1a8b83e0fa0b00eb096616b0bbf3092e275112cb5ebf95f0c28dcb\
    17d270e163b7f74fbfe7a0e16d0757d09aed787ec958ea42cc6e2aa6fd23e51297ac5713f2d28858da1e3b6c81ab\
    9c0596213b116fb8c7a0e7b6eeb4f25f44d789b33998aceeb3f25358204c22de7527c843a34c273d212b3887541e\
    c23e33698f786b39af72b07af4ca428e32a61350cef81fe2cd20209a86caa124cce6b462ec38a88a2ff18236fbad\
    4c1ce41c7ea47bfedbfd5788156be0c0417f014fc79cfa86ef23b459ea581956cb8744c9771aae5590e73f620544\
    2ce8908444ef0d272d820dcc84a6ba052cfe2a7cde358472c7c69419d8ec87a8e88d37c120956b5b5903ef765e59\
    ad0f6e2a1e2bc9778bb12aa0b0f71cee458843e9407269add5d2fa7a219e7c3a9200eadbab96bdf788b8cdacbb9b\
    42b4297292f8cbc543f5a2443cd4428b15f1ac479c7e082584d3e4b2e469c0d00cd2e40f50d69dbacc74c9c87ca1\
    35cc13ff28cbc9b5d6ad459db9b62fd10695e616aa3865ee052c72599d5f9b452c6dc9fb0d76698da79351b4cec4\
    f521559064a6b9e5280232349a9a146a1c8f33fc63ad7ca6cac53dfef25e93d00b5f1373383005584590ea4ff4bf\
    65084408f5c6744559f096b5c1f0fef553c5008378903160cd44795672367e808667a284749c38dc7fde4656bc41\
    68d50a0fed0a0363d4efd4a6af093093c76424f83270aeefb8e558280ab1246b14c114b33f0c94a4849eb79888c"

clave = "waifus1234567890"

descifrado = descifrar_hexadecimal(cifrado, clave)
print("- Mensaje descifrado: \n", descifrado)




















import secrets
import string

def generar_contrasena(longitud, incluir_mayusculas, incluir_minusculas, incluir_numeros, incluir_simbolos, caracteres_prohibidos=None):
    caracteres_posibles = ""
    
    if incluir_mayusculas:
        caracteres_posibles += string.ascii_uppercase
    if incluir_minusculas:
        caracteres_posibles += string.ascii_lowercase
    if incluir_numeros:
        caracteres_posibles += string.digits
    if incluir_simbolos:
        caracteres_posibles += string.punctuation
    
    if caracteres_prohibidos:
        for caracter in caracteres_prohibidos:
            caracteres_posibles = caracteres_posibles.replace(caracter, '')
    
    if len(caracteres_posibles) < longitud:
        raise ValueError("No hay suficientes caracteres posibles para generar una contraseña de la longitud especificada")
    
    contrasena = ''.join(secrets.choice(caracteres_posibles) for _ in range(longitud))
    return contrasena

def main():
    print("Generador de contraseñas seguras")
    
    while True:
        try:
            longitud = int(input("Ingrese la longitud de la contraseña (mínimo 8 caracteres): "))
            if longitud < 8:
                print("La longitud mínima de la contraseña es 8 caracteres")
                continue
            break
        except ValueError:
            print("Ingrese un número entero válido")
    
    # Pedir opciones de inclusión de caracteres
    incluir_mayusculas = input("¿Incluir mayúsculas? (s/n): ").lower() == 's'
    incluir_minusculas = input("¿Incluir minúsculas? (s/n): ").lower() == 's'
    incluir_numeros = input("¿Incluir números? (s/n): ").lower() == 's'
    incluir_simbolos = input("¿Incluir símbolos? (s/n): ").lower() == 's'
    
    caracteres_prohibidos = input("Ingrese los caracteres que no debe incluir la contraseña (opcional): ")
    if caracteres_prohibidos:
        caracteres_prohibidos = list(caracteres_prohibidos)
    else:
        caracteres_prohibidos = None
    
    try:
        contrasena = generar_contrasena(longitud, incluir_mayusculas, incluir_minusculas, incluir_numeros, incluir_simbolos, caracteres_prohibidos)
        print("Contraseña generada:", contrasena)
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()

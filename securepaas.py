import secrets
import string

def generar_contrasena(longitud, caracteres_prohibidos=None):
    caracteres_posibles = string.ascii_letters + string.digits + string.punctuation
    
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
    
    caracteres_prohibidos = input("Ingrese los caracteres que no debe incluir la contraseña (opcional): ")
    if caracteres_prohibidos:
        caracteres_prohibidos = list(caracteres_prohibidos)
    else:
        caracteres_prohibidos = None
    
    try:
        contrasena = generar_contrasena(longitud, caracteres_prohibidos)
        print("Contraseña generada:", contrasena)
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()

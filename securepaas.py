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

def calcular_fuerza(contrasena):
    """Calcula la fuerza de una contraseña basada en su longitud y diversidad de caracteres"""
    longitud = len(contrasena)
    tipos_caracteres = 0
    
    if any(c.isupper() for c in contrasena):
        tipos_caracteres += 1
    if any(c.islower() for c in contrasena):
        tipos_caracteres += 1
    if any(c.isdigit() for c in contrasena):
        tipos_caracteres += 1
    if any(c in string.punctuation for c in contrasena):
        tipos_caracteres += 1
    
    return longitud * tipos_caracteres

def guardar_contrasena(contrasena, archivo="contraseñas.txt"):
    """Guarda la contraseña generada en un archivo"""
    with open(archivo, 'a') as f:
        f.write(f"{contrasena}\n")
    print(f"Contraseña guardada en {archivo}")

def mostrar_estadisticas(contrasena):
    """Muestra estadísticas sobre la contraseña generada"""
    print("\nEstadísticas de la contraseña:")
    print(f"Longitud: {len(contrasena)} caracteres")
    print(f"Mayúsculas: {sum(1 for c in contrasena if c.isupper())}")
    print(f"Minúsculas: {sum(1 for c in contrasena if c.islower())}")
    print(f"Números: {sum(1 for c in contrasena if c.isdigit())}")
    print(f"Símbolos: {sum(1 for c in contrasena if c in string.punctuation)}")
    print(f"Fuerza estimada: {calcular_fuerza(contrasena)}")

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
        print("\nContraseña generada:", contrasena)
        
        # Mostrar estadísticas
        mostrar_estadisticas(contrasena)
        
        # Opción para guardar la contraseña
        guardar = input("\n¿Desea guardar esta contraseña? (s/n): ").lower() == 's'
        if guardar:
            guardar_contrasena(contrasena)
            
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()

import secrets
import string
from typing import Optional, List
import json
import os

class PasswordGenerator:
    """Clase para generar y gestionar contraseñas seguras"""
    
    def __init__(self):
        self.saved_passwords_file = "passwords.json"
        self.password_history = self._load_password_history()
    
    def _load_password_history(self) -> List[dict]:
        """Carga el historial de contraseñas desde archivo"""
        if os.path.exists(self.saved_passwords_file):
            with open(self.saved_passwords_file, 'r') as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return []
        return []
    
    def _save_password_history(self):
        """Guarda el historial de contraseñas en archivo"""
        with open(self.saved_passwords_file, 'w') as f:
            json.dump(self.password_history, f, indent=2)
    
    def generate_password(
        self,
        length: int,
        use_uppercase: bool,
        use_lowercase: bool,
        use_numbers: bool,
        use_symbols: bool,
        excluded_chars: Optional[str] = None
    ) -> str:
        """
        Genera una contraseña segura con los parámetros especificados
        
        Args:
            length: Longitud de la contraseña (mínimo 8)
            use_uppercase: Incluir mayúsculas
            use_lowercase: Incluir minúsculas
            use_numbers: Incluir números
            use_symbols: Incluir símbolos
            excluded_chars: Caracteres a excluir
            
        Returns:
            str: Contraseña generada
            
        Raises:
            ValueError: Si no hay suficientes caracteres disponibles
        """
        if length < 8:
            raise ValueError("La longitud mínima es 8 caracteres")
        
        char_pool = []
        char_sets = {
            'uppercase': (use_uppercase, string.ascii_uppercase),
            'lowercase': (use_lowercase, string.ascii_lowercase),
            'numbers': (use_numbers, string.digits),
            'symbols': (use_symbols, string.punctuation)
        }
        
        for name, (enabled, chars) in char_sets.items():
            if enabled:
                char_pool.extend(chars)
        
        if excluded_chars:
            char_pool = [c for c in char_pool if c not in excluded_chars]
        
        if not char_pool:
            raise ValueError("No hay caracteres disponibles para generar la contraseña")
        
        if len(char_pool) < length:
            raise ValueError(f"Se necesitan al menos {length} caracteres distintos")
        
        return ''.join(secrets.choice(char_pool) for _ in range(length))
    
    def calculate_password_strength(self, password: str) -> dict:
        """
        Calcula métricas de seguridad de la contraseña
        
        Args:
            password: Contraseña a analizar
            
        Returns:
            dict: Diccionario con métricas de seguridad
        """
        metrics = {
            'length': len(password),
            'uppercase': sum(1 for c in password if c.isupper()),
            'lowercase': sum(1 for c in password if c.islower()),
            'numbers': sum(1 for c in password if c.isdigit()),
            'symbols': sum(1 for c in password if c in string.punctuation),
        }
        
        # Calcular entropía (medida de seguridad)
        char_variety = sum(1 for k in ['uppercase', 'lowercase', 'numbers', 'symbols'] if metrics[k] > 0)
        metrics['entropy'] = metrics['length'] * char_variety
        
        # Estimación de tiempo para crackear
        if metrics['entropy'] < 40:
            metrics['crack_time'] = "Segundos"
        elif metrics['entropy'] < 60:
            metrics['crack_time'] = "Horas"
        elif metrics['entropy'] < 80:
            metrics['crack_time'] = "Años"
        else:
            metrics['crack_time'] = "Siglos"
        
        return metrics
    
    def save_password(self, password: str, purpose: str = ""):
        """
        Guarda una contraseña en el historial con su propósito
        
        Args:
            password: Contraseña a guardar
            purpose: Descripción del uso de la contraseña
        """
        self.password_history.append({
            'password': password,
            'purpose': purpose,
            'strength': self.calculate_password_strength(password),
            'timestamp': datetime.datetime.now().isoformat()
        })
        self._save_password_history()
    
    def get_password_history(self) -> List[dict]:
        """Devuelve el historial de contraseñas generadas"""
        return self.password_history

def get_user_input(prompt: str, input_type=str, validation_func=None) -> any:
    """
    Obtiene entrada del usuario con validación
    
    Args:
        prompt: Mensaje a mostrar al usuario
        input_type: Tipo de dato esperado
        validation_func: Función para validar el input
        
    Returns:
        Valor validado introducido por el usuario
    """
    while True:
        try:
            user_input = input_type(input(prompt).strip())
            if validation_func and not validation_func(user_input):
                raise ValueError
            return user_input
        except ValueError:
            print(f"Entrada inválida. Por favor ingrese un valor válido ({input_type.__name__})")

def main():
    print("=== GENERADOR DE CONTRASEÑAS SEGURAS ===")
    generator = PasswordGenerator()
    
    # Configuración de la contraseña
    length = get_user_input(
        "Longitud de la contraseña (8-64): ",
        int,
        lambda x: 8 <= x <= 64
    )
    
    print("\nTipos de caracteres a incluir:")
    use_upper = get_user_input("Incluir mayúsculas? (s/n): ", str, lambda x: x.lower() in ['s', 'n']).lower() == 's'
    use_lower = get_user_input("Incluir minúsculas? (s/n): ", str, lambda x: x.lower() in ['s', 'n']).lower() == 's'
    use_nums = get_user_input("Incluir números? (s/n): ", str, lambda x: x.lower() in ['s', 'n']).lower() == 's'
    use_syms = get_user_input("Incluir símbolos? (s/n): ", str, lambda x: x.lower() in ['s', 'n']).lower() == 's'
    
    excluded = get_user_input(
        "Caracteres a excluir (opcional, dejar vacío para ninguno): ",
        str,
        lambda x: True
    ) or None
    
    # Generar contraseña
    try:
        password = generator.generate_password(
            length, use_upper, use_lower, use_nums, use_syms, excluded
        )
        
        print(f"\n🔒 Contraseña generada: {password}\n")
        
        # Mostrar estadísticas
        stats = generator.calculate_password_strength(password)
        print("📊 Estadísticas de seguridad:")
        print(f"  • Longitud: {stats['length']} caracteres")
        print(f"  • Mayúsculas: {stats['uppercase']}")
        print(f"  • Minúsculas: {stats['lowercase']}")
        print(f"  • Números: {stats['numbers']}")
        print(f"  • Símbolos: {stats['symbols']}")
        print(f"  • Entropía: {stats['entropy']} bits")
        print(f"  • Tiempo estimado para crackear: {stats['crack_time']}")
        
        # Opción para guardar
        if get_user_input("\n¿Guardar esta contraseña? (s/n): ", str, lambda x: x.lower() in ['s', 'n']).lower() == 's':
            purpose = get_user_input("Propósito/uso de esta contraseña: ", str)
            generator.save_password(password, purpose)
            print("✅ Contraseña guardada en el historial")
            
    except ValueError as e:
        print(f"\n❌ Error: {e}")
    
    print("\nGracias por usar el generador de contraseñas seguras")

if __name__ == "__main__":
    import datetime
    main()

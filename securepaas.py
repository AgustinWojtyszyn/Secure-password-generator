import secrets
import string
from typing import Optional, List, Dict, Any
import json
import os
from datetime import datetime
from enum import Enum, auto
import hashlib
from pathlib import Path


class PasswordStrength(Enum):
    WEAK = auto()
    MEDIUM = auto()
    STRONG = auto()
    VERY_STRONG = auto()


class PasswordGenerator:
    """Clase para generar y gestionar contraseñas seguras con persistencia"""
    
    def __init__(self, storage_file: str = "passwords.json"):
        self.storage_file = Path(storage_file)
        self.password_history: List[Dict[str, Any]] = self._load_password_history()
    
    def _load_password_history(self) -> List[Dict[str, Any]]:
        """Carga el historial de contraseñas desde archivo con manejo de errores"""
        if not self.storage_file.exists():
            return []
            
        try:
            with open(self.storage_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Could not load password history - {str(e)}")
            return []
    
    def _save_password_history(self) -> None:
        """Guarda el historial de contraseñas en archivo con manejo de errores"""
        try:
            with open(self.storage_file, 'w', encoding='utf-8') as f:
                json.dump(self.password_history, f, indent=2, ensure_ascii=False)
        except OSError as e:
            print(f"Error: Could not save password history - {str(e)}")
    
    def _validate_character_pool(
        self, 
        char_pool: List[str], 
        min_length: int
    ) -> None:
        """Valida que el conjunto de caracteres sea adecuado"""
        if not char_pool:
            raise ValueError("No hay caracteres disponibles para generar la contraseña")
        
        if len(char_pool) < min_length:
            raise ValueError(
                f"El conjunto de caracteres es demasiado pequeño. "
                f"Se necesitan al menos {min_length} caracteres distintos."
            )
    
    def generate_password(
        self,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_numbers: bool = True,
        use_symbols: bool = True,
        excluded_chars: Optional[str] = None,
        min_char_types: int = 3
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
            min_char_types: Mínimo tipos de caracteres requeridos
            
        Returns:
            str: Contraseña generada
            
        Raises:
            ValueError: Si no hay suficientes caracteres disponibles
        """
        if length < 8:
            raise ValueError("La longitud mínima es 8 caracteres")
        
        char_sets = {
            'uppercase': (use_uppercase, string.ascii_uppercase),
            'lowercase': (use_lowercase, string.ascii_lowercase),
            'numbers': (use_numbers, string.digits),
            'symbols': (use_symbols, string.punctuation)
        }
        
        # Filtrar conjuntos de caracteres no utilizados
        char_pool = []
        enabled_sets = []
        
        for name, (enabled, chars) in char_sets.items():
            if enabled:
                char_pool.extend(chars)
                enabled_sets.append(name)
        
        if len(enabled_sets) < min_char_types:
            raise ValueError(
                f"Se requieren al menos {min_char_types} tipos de caracteres. "
                f"Tipos habilitados: {', '.join(enabled_sets)}"
            )
        
        if excluded_chars:
            char_pool = [c for c in char_pool if c not in excluded_chars]
        
        self._validate_character_pool(char_pool, length)
        
        # Generar contraseña asegurando al menos un carácter de cada tipo habilitado
        password = []
        for char_set in enabled_sets:
            password.append(secrets.choice(char_sets[char_set][1]))
        
        # Completar el resto de la contraseña
        remaining_length = length - len(password)
        password.extend(secrets.choice(char_pool) for _ in range(remaining_length))
        
        # Mezclar los caracteres para mayor aleatoriedad
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def calculate_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Calcula métricas de seguridad de la contraseña
        
        Args:
            password: Contraseña a analizar
            
        Returns:
            dict: Diccionario con métricas de seguridad
        """
        if not password:
            raise ValueError("La contraseña no puede estar vacía")
        
        metrics = {
            'length': len(password),
            'uppercase': sum(1 for c in password if c.isupper()),
            'lowercase': sum(1 for c in password if c.islower()),
            'numbers': sum(1 for c in password if c.isdigit()),
            'symbols': sum(1 for c in password if c in string.punctuation),
            'unique_chars': len(set(password)),
            'entropy': 0,
            'strength': PasswordStrength.WEAK.name,
            'crack_time': "Instantáneo"
        }
        
        # Calcular entropía (medida más precisa)
        char_variety = 0
        pool_size = 0
        
        if metrics['uppercase'] > 0:
            pool_size += len(string.ascii_uppercase)
            char_variety += 1
        if metrics['lowercase'] > 0:
            pool_size += len(string.ascii_lowercase)
            char_variety += 1
        if metrics['numbers'] > 0:
            pool_size += len(string.digits)
            char_variety += 1
        if metrics['symbols'] > 0:
            pool_size += len(string.punctuation)
            char_variety += 1
        
        if pool_size > 0:
            metrics['entropy'] = len(password) * (pool_size ** 0.5)
        
        # Evaluar fuerza de la contraseña
        if metrics['entropy'] < 40 or metrics['length'] < 8:
            metrics['strength'] = PasswordStrength.WEAK.name
            metrics['crack_time'] = "Segundos a minutos"
        elif metrics['entropy'] < 60:
            metrics['strength'] = PasswordStrength.MEDIUM.name
            metrics['crack_time'] = "Horas a días"
        elif metrics['entropy'] < 80:
            metrics['strength'] = PasswordStrength.STRONG.name
            metrics['crack_time'] = "Meses a años"
        else:
            metrics['strength'] = PasswordStrength.VERY_STRONG.name
            metrics['crack_time'] = "Décadas a siglos"
        
        return metrics
    
    def save_password(
        self, 
        password: str, 
        purpose: str = "",
        tags: Optional[List[str]] = None
    ) -> None:
        """
        Guarda una contraseña en el historial con metadatos
        
        Args:
            password: Contraseña a guardar
            purpose: Descripción del uso de la contraseña
            tags: Etiquetas para categorizar la contraseña
        """
        if not password:
            raise ValueError("La contraseña no puede estar vacía")
        
        # No almacenar la contraseña directamente, sino un hash
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        entry = {
            'password_hash': password_hash,
            'purpose': purpose,
            'tags': tags or [],
            'strength': self.calculate_password_strength(password),
            'timestamp': datetime.now().isoformat()
        }
        
        self.password_history.append(entry)
        self._save_password_history()
    
    def get_password_history(self) -> List[Dict[str, Any]]:
        """Devuelve una copia del historial de contraseñas generadas"""
        return self.password_history.copy()
    
    def search_passwords(self, search_term: str) -> List[Dict[str, Any]]:
        """
        Busca contraseñas en el historial por propósito o etiquetas
        
        Args:
            search_term: Término de búsqueda
            
        Returns:
            Lista de entradas que coinciden con el término de búsqueda
        """
        return [
            entry for entry in self.password_history
            if (search_term.lower() in entry['purpose'].lower() or
                any(search_term.lower() in tag.lower() for tag in entry.get('tags', [])))
        ]


def get_user_input(
    prompt: str,
    input_type: type = str,
    validation_func: Optional[callable] = None,
    error_msg: Optional[str] = None
) -> Any:
    """
    Obtiene entrada del usuario con validación robusta
    
    Args:
        prompt: Mensaje a mostrar al usuario
        input_type: Tipo de dato esperado
        validation_func: Función para validar el input
        error_msg: Mensaje de error personalizado
        
    Returns:
        Valor validado introducido por el usuario
    """
    while True:
        try:
            user_input = input(prompt).strip()
            if input_type != str:
                user_input = input_type(user_input)
            
            if validation_func and not validation_func(user_input):
                raise ValueError(error_msg or f"Entrada inválida. Por favor ingrese un valor válido")
            
            return user_input
        except ValueError as e:
            print(f"Error: {str(e)}")


def display_password_strength(stats: Dict[str, Any]) -> None:
    """Muestra las estadísticas de seguridad de la contraseña de forma legible"""
    print("\n📊 Estadísticas de seguridad:")
    print(f"  • Longitud: {stats['length']} caracteres")
    print(f"  • Caracteres únicos: {stats['unique_chars']}")
    print(f"  • Mayúsculas: {stats['uppercase']}")
    print(f"  • Minúsculas: {stats['lowercase']}")
    print(f"  • Números: {stats['numbers']}")
    print(f"  • Símbolos: {stats['symbols']}")
    print(f"  • Entropía: {stats['entropy']:.2f} bits")
    print(f"  • Fuerza: {stats['strength']}")
    print(f"  • Tiempo estimado para crackear: {stats['crack_time']}")


def main_menu() -> None:
    """Menú principal de la aplicación"""
    print("\n=== GENERADOR DE CONTRASEÑAS SEGURAS ===")
    print("1. Generar nueva contraseña")
    print("2. Ver historial de contraseñas")
    print("3. Buscar en contraseñas guardadas")
    print("4. Salir")


def password_generation_flow(generator: PasswordGenerator) -> None:
    """Flujo para generar una nueva contraseña"""
    print("\n--- Configuración de la contraseña ---")
    
    length = get_user_input(
        "Longitud de la contraseña (8-128, recomendado 12-16): ",
        int,
        lambda x: 8 <= x <= 128,
        "La longitud debe estar entre 8 y 128 caracteres"
    )
    
    print("\nTipos de caracteres a incluir (recomendado habilitar al menos 3):")
    use_upper = get_user_input(
        "Incluir mayúsculas? (s/n): ", 
        str, 
        lambda x: x.lower() in ['s', 'n']
    ).lower() == 's'
    use_lower = get_user_input(
        "Incluir minúsculas? (s/n): ", 
        str, 
        lambda x: x.lower() in ['s', 'n']
    ).lower() == 's'
    use_nums = get_user_input(
        "Incluir números? (s/n): ", 
        str, 
        lambda x: x.lower() in ['s', 'n']
    ).lower() == 's'
    use_syms = get_user_input(
        "Incluir símbolos? (s/n): ", 
        str, 
        lambda x: x.lower() in ['s', 'n']
    ).lower() == 's'
    
    excluded = get_user_input(
        "Caracteres a excluir (opcional, dejar vacío para ninguno): ",
        str
    ) or None
    
    try:
        password = generator.generate_password(
            length=length,
            use_uppercase=use_upper,
            use_lowercase=use_lower,
            use_numbers=use_nums,
            use_symbols=use_syms,
            excluded_chars=excluded
        )
        
        print(f"\n🔒 Contraseña generada: {password}")
        
        stats = generator.calculate_password_strength(password)
        display_password_strength(stats)
        
        if get_user_input(
            "\n¿Guardar esta contraseña? (s/n): ",
            str,
            lambda x: x.lower() in ['s', 'n']
        ).lower() == 's':
            purpose = get_user_input("Propósito/uso de esta contraseña: ", str)
            tags = get_user_input(
                "Etiquetas para categorizar (separadas por comas, opcional): ",
                str
            )
            tag_list = [t.strip() for t in tags.split(',')] if tags else []
            
            generator.save_password(password, purpose, tag_list)
            print("✅ Contraseña guardada en el historial")
            
    except ValueError as e:
        print(f"\n❌ Error: {e}")


def view_history(generator: PasswordGenerator) -> None:
    """Muestra el historial de contraseñas generadas"""
    history = generator.get_password_history()
    if not history:
        print("\nNo hay contraseñas en el historial.")
        return
    
    print("\n--- Historial de Contraseñas ---")
    for idx, entry in enumerate(history, 1):
        print(f"\nEntrada #{idx}:")
        print(f"  • Propósito: {entry['purpose']}")
        print(f"  • Fecha: {entry['timestamp']}")
        print(f"  • Fuerza: {entry['strength']['strength']}")
        print(f"  • Etiquetas: {', '.join(entry.get('tags', []))}")


def search_history(generator: PasswordGenerator) -> None:
    """Busca en el historial de contraseñas"""
    search_term = get_user_input(
        "\nIngrese término de búsqueda (propósito o etiquetas): ",
        str
    )
    
    results = generator.search_passwords(search_term)
    if not results:
        print("\nNo se encontraron coincidencias.")
        return
    
    print(f"\n--- Resultados de búsqueda ({len(results)}) ---")
    for idx, entry in enumerate(results, 1):
        print(f"\nResultado #{idx}:")
        print(f"  • Propósito: {entry['purpose']}")
        print(f"  • Fecha: {entry['timestamp']}")
        print(f"  • Fuerza: {entry['strength']['strength']}")
        print(f"  • Etiquetas: {', '.join(entry.get('tags', []))}")


def main() -> None:
    """Función principal de la aplicación"""
    generator = PasswordGenerator()
    
    while True:
        main_menu()
        choice = get_user_input(
            "\nSeleccione una opción (1-4): ",
            int,
            lambda x: 1 <= x <= 4,
            "Por favor ingrese un número entre 1 y 4"
        )
        
        if choice == 1:
            password_generation_flow(generator)
        elif choice == 2:
            view_history(generator)
        elif choice == 3:
            search_history(generator)
        elif choice == 4:
            print("\nGracias por usar el generador de contraseñas seguras. ¡Hasta pronto!")
            break
        
        input("\nPresione Enter para continuar...")


if __name__ == "__main__":
    main()

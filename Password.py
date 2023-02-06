import hashlib

def validate_password(password):
    """
    Vérifie si le mot de passe répond aux exigences de sécurité
    """
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in "!@#$%^&*" for char in password):
        return False
    return True

def hash_password(password):
    """
    Crypte le mot de passe en utilisant l'algorithme SHA-256
    """
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    """
    Fonction principale pour demander et vérifier le mot de passe
    """
    password = input("Choisissez un mot de passe: ")

    while not validate_password(password):
        print("Mot de passe non valide. Veuillez respecter les exigences de sécurité.")
        password = input("Choisissez un nouveau mot de passe: ")

    print("Mot de passe valide.")

    hashed_password = hash_password(password)
    print("Mot de passe crypté:", hashed_password)

# Appeler la fonction principale
if __name__ == '__main__':
    main()
import json
import os
import secrets
import string
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from getpass import getpass
import base64

class PasswordManager:
    def __init__(self, data_file="vault.enc", key_file="master.key"):
        self.data_file = data_file
        self.key_file = key_file
        self.vault = {}
        self.master_key = None
        self.salt = None
        
    def initialize(self):
        """Initialize or load the password vault"""
        if os.path.exists(self.key_file) and os.path.exists(self.data_file):
            self._load_vault()
        else:
            self._create_new_vault()

    def _create_new_vault(self):
        """Create a new encrypted vault"""
        master_password = getpass("Create a master password: ")
        verify_password = getpass("Verify master password: ")
        
        if master_password != verify_password:
            raise ValueError("Passwords do not match")
            
        self.salt = get_random_bytes(16)
        self.master_key, _ = self._derive_key(master_password, self.salt)
        
        # Save the salt and hashed master password for verification
        hashed_master = self._hash_value(master_password)
        with open(self.key_file, 'wb') as f:
            f.write(self.salt)
            f.write(hashed_master)
            
        print("New vault created successfully")

    def _load_vault(self):
        """Load an existing encrypted vault"""
        with open(self.key_file, 'rb') as f:
            self.salt = f.read(16)
            stored_hash = f.read(32)  # SHA-256 hash is 32 bytes
            
        attempts = 3
        while attempts > 0:
            master_password = getpass("Enter master password: ")
            hashed_attempt = self._hash_value(master_password)
            
            if hashed_attempt == stored_hash:
                self.master_key, _ = self._derive_key(master_password, self.salt)
                self._decrypt_vault()
                print("Vault unlocked successfully")
                return
            else:
                attempts -= 1
                print(f"Invalid password. {attempts} attempts remaining.")
                
        raise PermissionError("Too many failed attempts")

    def _hash_value(self, value):
        """Hash a value using SHA-256"""
        return hashlib.sha256(value.encode()).digest()

    def _derive_key(self, password, salt):
        """Derive a 256-bit key from password using PBKDF2"""
        return PBKDF2(password, salt, dkLen=32, count=100000), salt

    def generate_password(self, length=20, use_symbols=True):
        """Generate a strong random password"""
        chars = string.ascii_letters + string.digits
        if use_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(chars) for _ in range(length))

    def add_credential(self, service, username, password=None):
        """Add a new credential to the vault"""
        if service in self.vault:
            raise ValueError("Service already exists")
            
        password = password or self.generate_password()
        
        # Store hashed versions of sensitive data
        self.vault[service] = {
            "username_hash": self._hash_value(username).hex(),
            "password_hash": self._hash_value(password).hex(),
            "service_hash": self._hash_value(service).hex(),
            "username": self._encrypt_data(username),
            "password": self._encrypt_data(password),
            "service": self._encrypt_data(service)
        }
        
        print(f"Added credentials for {service}")

    def get_credential(self, service):
        """Retrieve a credential from the vault"""
        if service not in self.vault:
            raise ValueError("Service not found")
            
        # Verify the service name hash matches
        service_hash = self._hash_value(service).hex()
        if service_hash != self.vault[service]["service_hash"]:
            raise ValueError("Service verification failed")
            
        # Decrypt and return the credentials
        return {
            "service": self._decrypt_data(self.vault[service]["service"]),
            "username": self._decrypt_data(self.vault[service]["username"]),
            "password": self._decrypt_data(self.vault[service]["password"])
        }

    def _encrypt_data(self, data):
        """Encrypt data using AES"""
        iv = get_random_bytes(16)
        cipher = AES.new(self.master_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted).decode()

    def _decrypt_data(self, encrypted_data):
        """Decrypt data using AES"""
        data = base64.b64decode(encrypted_data.encode())
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(self.master_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    def _encrypt_vault(self):
        """Encrypt the entire vault before saving"""
        iv = get_random_bytes(16)
        cipher = AES.new(self.master_key, AES.MODE_CBC, iv)
        vault_json = json.dumps(self.vault).encode()
        encrypted = cipher.encrypt(pad(vault_json, AES.block_size))
        return iv + encrypted

    def _decrypt_vault(self):
        """Decrypt the vault after loading"""
        if not os.path.exists(self.data_file):
            self.vault = {}
            return
            
        with open(self.data_file, 'rb') as f:
            data = f.read()
            
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(self.master_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        self.vault = json.loads(decrypted.decode())

    def save_vault(self):
        """Save the encrypted vault to disk"""
        encrypted_data = self._encrypt_vault()
        with open(self.data_file, 'wb') as f:
            f.write(encrypted_data)
        print("Vault saved and encrypted successfully")

def main():
    pm = PasswordManager()
    pm.initialize()
    
    while True:
        print("\nPassword Manager Menu:")
        print("1. Add new credential")
        print("2. Get credential")
        print("3. Generate random password")
        print("4. Exit")
        
        choice = input("Choose an option: ")
        
        try:
            if choice == "1":
                service = input("Service/Website: ")
                username = input("Username: ")
                if input("Generate password? (y/n): ").lower() == 'y':
                    pm.add_credential(service, username)
                else:
                    password = getpass("Password: ")
                    pm.add_credential(service, username, password)
                    
            elif choice == "2":
                service = input("Service/Website: ")
                creds = pm.get_credential(service)
                print(f"\nService: {creds['service']}")
                print(f"Username: {creds['username']}")
                print(f"Password: {creds['password']}")
                
            elif choice == "3":
                length = int(input("Password length: "))
                symbols = input("Include symbols? (y/n): ").lower() == 'y'
                print(f"Generated password: {pm.generate_password(length, symbols)}")
                
            elif choice == "4":
                pm.save_vault()
                print("Goodbye!")
                break
                
            else:
                print("Invalid choice")
                
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
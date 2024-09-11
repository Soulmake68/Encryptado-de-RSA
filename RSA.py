import sys
import os
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QFileDialog, QLabel, QLineEdit, QRadioButton, QButtonGroup
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Generar un par de claves RSA
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Serializar las claves
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private, pem_public

# Encriptar un mensaje
def encrypt_message(message, pem_public):
    public_key = serialization.load_pem_public_key(pem_public)
    
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_message

# Desencriptar un mensaje
def decrypt_message(encrypted_message, pem_private):
    private_key = serialization.load_pem_private_key(pem_private, password=None)
    
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted_message.decode()

# Ventana principal
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Encriptador/Desencriptador de Contraseñas RSA')
        self.setGeometry(100, 100, 600, 500)
        
        # Crear widgets
        self.passwords_text_edit = QTextEdit(self)
        self.passwords_text_edit.setPlaceholderText("Introduce contraseñas aquí (una por línea). Escribe 'FIN' en una línea para terminar.")
        
        self.output_dir_label = QLabel("Ruta del archivo de salida:", self)
        self.output_dir_line_edit = QLineEdit(self)
        
        self.browse_button = QPushButton("Buscar...", self)
        self.browse_button.clicked.connect(self.browse_output_directory)
        
        self.encrypt_radio = QRadioButton("Encriptar", self)
        self.decrypt_radio = QRadioButton("Desencriptar", self)
        self.encrypt_radio.setChecked(True)  # Predeterminado a encriptar
        
        self.operation_group = QButtonGroup(self)
        self.operation_group.addButton(self.encrypt_radio)
        self.operation_group.addButton(self.decrypt_radio)
        
        self.process_button = QPushButton("Procesar Contraseñas", self)
        self.process_button.clicked.connect(self.process_passwords)
        
        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.passwords_text_edit)
        layout.addWidget(self.output_dir_label)
        layout.addWidget(self.output_dir_line_edit)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.encrypt_radio)
        layout.addWidget(self.decrypt_radio)
        layout.addWidget(self.process_button)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
    
    def browse_output_directory(self):
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar Directorio de Salida")
        if folder:
            self.output_dir_line_edit.setText(folder)
    
    def process_passwords(self):
        operation = 'encrypt' if self.encrypt_radio.isChecked() else 'decrypt'
        passwords = self.passwords_text_edit.toPlainText().splitlines()
        
        # Eliminar cualquier línea vacía y 'FIN'
        passwords = [p for p in passwords if p.strip() and p.strip().upper() != 'FIN']
        
        if not passwords:
            self.statusBar().showMessage("No hay contraseñas para procesar.")
            return
        
        output_dir = self.output_dir_line_edit.text().strip()
        if not os.path.exists(output_dir):
            self.statusBar().showMessage(f"La ruta especificada no existe: {output_dir}")
            return
        
        if operation == 'encrypt':
            # Generar un par de claves RSA
            private_key, public_key = generate_rsa_key_pair()
            
            # Guardar las claves en archivos
            with open('private_key.pem', 'wb') as f:
                f.write(private_key)
            
            with open('public_key.pem', 'wb') as f:
                f.write(public_key)
            
            # Crear un nombre de archivo basado en la fecha y hora actual
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            output_file = os.path.join(output_dir, f"encrypted_passwords_{timestamp}.txt")
            
            # Encriptar las contraseñas y guardarlas en el archivo especificado
            encrypted_passwords = []
            for password in passwords:
                encrypted = encrypt_message(password, public_key)
                encrypted_passwords.append(encrypted.hex())  # Convertir a hexadecimal para almacenamiento
            
            with open(output_file, 'w') as f:
                for encrypted in encrypted_passwords:
                    f.write(encrypted + '\n')
            
            self.statusBar().showMessage(f"Contraseñas encriptadas guardadas en {output_file}")
        
        elif operation == 'decrypt':
            private_key_file = QFileDialog.getOpenFileName(self, "Seleccionar archivo de clave privada", "", "Archivos PEM (*.pem)")[0]
            if not private_key_file:
                self.statusBar().showMessage("No se seleccionó un archivo de clave privada.")
                return
            
            # Cargar clave privada
            with open(private_key_file, 'rb') as f:
                private_key = f.read()
            
            # Crear un nombre de archivo basado en la fecha y hora actual
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            output_file = os.path.join(output_dir, f"decrypted_passwords_{timestamp}.txt")
            
            # Desencriptar las contraseñas y guardarlas en el archivo especificado
            decrypted_passwords = []
            for password in passwords:
                try:
                    encrypted_message = bytes.fromhex(password)  # Convertir de hexadecimal a bytes
                    decrypted = decrypt_message(encrypted_message, private_key)
                    decrypted_passwords.append(decrypted)
                except Exception as e:
                    self.statusBar().showMessage(f"Error al desencriptar: {e}")
                    return
            
            with open(output_file, 'w') as f:
                for decrypted in decrypted_passwords:
                    f.write(decrypted + '\n')
            
            self.statusBar().showMessage(f"Contraseñas desencriptadas guardadas en {output_file}")

# Ejecutar la aplicación
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

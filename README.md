# Encriptador/Desencriptador de Contraseñas RSA

Este proyecto es una aplicación de escritorio desarrollada en Python utilizando PyQt5 para la interfaz gráfica y la biblioteca `cryptography` para la criptografía RSA. La aplicación permite encriptar y desencriptar contraseñas usando un par de claves RSA generadas automáticamente.

## Características

- **Generación de Claves RSA**: La aplicación genera un par de claves RSA (pública y privada) para realizar encriptación y desencriptación.
- **Encriptación de Contraseñas**: Permite encriptar contraseñas introducidas en la aplicación y guardarlas en un archivo.
- **Desencriptación de Contraseñas**: Permite desencriptar contraseñas previamente encriptadas si tienes el archivo de clave privada correspondiente.

## Requisitos

- **Python**: 3.x
- **PyQt5**: Para la interfaz gráfica de usuario.
- **cryptography**: Para operaciones criptográficas.

Puedes instalar las dependencias necesarias utilizando `pip`:


pip install PyQt5 cryptography

## Uso
Ejecutar la Aplicación: Ejecuta el archivo principal del proyecto:

Copiar código
python RSA.py
##Encriptar Contraseñas:

- Introduce las contraseñas (una por línea) en el campo de texto.
- Selecciona la opción "Encriptar".
- Especifica el directorio donde se guardarán las contraseñas encriptadas.
- Haz clic en "Procesar Contraseñas".
- La aplicación generará un par de claves RSA y guardará las contraseñas encriptadas en un archivo en el directorio especificado.
##Desencriptar Contraseñas:

- Introduce las contraseñas encriptadas (una por línea) en el campo de texto.
- Selecciona la opción "Desencriptar".
- Especifica el directorio donde se guardarán las contraseñas desencriptadas.
- Selecciona el archivo de clave privada (.pem) necesario para la desencriptación.
- Haz clic en "Procesar Contraseñas".
- La aplicación desencriptará las contraseñas y las guardará en un archivo en el directorio especificado.
- Archivos Generados
##Claves RSA:

- private_key.pem: Clave privada generada para la desencriptación.
- public_key.pem: Clave pública generada para la encriptación.
## Archivos de Contraseñas:

- encrypted_passwords_TIMESTAMP.txt: Archivo con contraseñas encriptadas, donde TIMESTAMP es la fecha y hora actuales.
- decrypted_passwords_TIMESTAMP.txt: Archivo con contraseñas desencriptadas, donde TIMESTAMP es la fecha y hora actuales.
##Código
#Aquí hay una breve descripción de las principales funciones del código:

- generate_rsa_key_pair: Genera un par de claves RSA (pública y privada).
- encrypt_message: Encripta un mensaje utilizando la clave pública RSA.
- decrypt_message: Desencripta un mensaje utilizando la clave privada RSA.
- MainWindow: La ventana principal de la aplicación, que permite al usuario ingresar contraseñas, seleccionar opciones de encriptación/desencriptación y especificar el directorio de salida.

## Contribución
Si deseas contribuir al proyecto, por favor, realiza un fork del repositorio y envía un pull request con tus cambios. Asegúrate de probar tus cambios y seguir las mejores prácticas de codificación.

import os
import ctypes
from getpass import getpass
import sys
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
import time

def print_progress(percentage):
    """Відображає прогрес у відсотках у консолі.
    :param percentage: Відсоток завершення (значення від 0 до 100)."""
    # Обмежуємо значення від 0 до 100
    percentage = max(0, min(percentage, 100))
    sys.stdout.write(f"\rПрогрес: {percentage:.2f}%")  # Оновлюємо поточний рядок
    sys.stdout.flush()  # Очищаємо буфер виводу, щоб відобразити текст негайно


# Функція для безпечного очищення пам'яті
def clear_sensitive_data(data: object):
    if isinstance(data, bytes):
        ctypes.memset(ctypes.addressof(ctypes.create_string_buffer(data)), 0, len(data))
    elif isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, memoryview):
        data[:] = b'\x00' * len(data)

# Клас для роботи з AES (Advanced Encryption Standard)
class AESFileCipher:
    def __init__(self, password: str):
        # Зберігаю пароль, генерую випадкові salt і IV (ініціалізаційний вектор)
        self.password = password.encode()  # Пароль у байтах
        self.salt = os.urandom(16)  # Salt для KDF
        self.iv = os.urandom(16)  # IV (Initialization Vector) для шифрування AES
        self.key = self._generate_key()  # Генеруємо AES ключ

    # Генерація AES-ключа на основі пароля та salt
    def _generate_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Хеш-функція для KDF
            length=32,  # Довжина ключа AES (256 біт)
            salt=self.salt,
            iterations=100000,  # Кількість ітерацій для посилення захисту
        )
        return kdf.derive(self.password)  # Генеруємо ключ

    # Шифрування файлу блоками
    def encrypt_file(self, input_file: str, output_file: str):
        try:
            file_size = os.path.getsize(input_file)  # Розмір файлу для розрахунку прогресу
            processed_size = 0  # Кількість оброблених байтів

            with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
                # Зберігаємо salt та IV на початку файлу
                f_out.write(self.salt + self.iv)

                # Читаємо дані блоками (наприклад, по 64 КБ)
                block_size = 64 * 1024
                padder = padding.PKCS7(128).padder()
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
                encryptor = cipher.encryptor()

                while chunk := f_in.read(block_size):
                    padded_data = padder.update(chunk)
                    encrypted_data = encryptor.update(padded_data)
                    f_out.write(encrypted_data)

                    # Оновлюємо прогрес
                    processed_size += len(chunk)
                    percentage = (processed_size / file_size) * 100
                    print_progress(percentage)

                # Додаємо фінальні байти
                final_padded_data = padder.finalize()
                final_encrypted_data = encryptor.update(final_padded_data) + encryptor.finalize()
                f_out.write(final_encrypted_data)


        finally:
            clear_sensitive_data(self.key)
            clear_sensitive_data(self.password)

    def decrypt_file(self, encrypted_file: str, output_file: str):
        try:
            file_size = os.path.getsize(encrypted_file)  # Розмір зашифрованого файлу
            processed_size = 0  # Кількість оброблених байтів

            with open(encrypted_file, "rb") as f_in, open(output_file, "wb") as f_out:
                # Зчитуємо salt та IV
                salt = f_in.read(16)
                iv = f_in.read(16)

                # Відновлюємо AES-ключ
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = kdf.derive(self.password)

                # Ініціалізуємо дешифратор
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                unpadder = padding.PKCS7(128).unpadder()

                block_size = 64 * 1024  # Розмір блоку
                while chunk := f_in.read(block_size):
                    decrypted_data = decryptor.update(chunk)
                    unpadded_data = unpadder.update(decrypted_data)
                    f_out.write(unpadded_data)

                    # Оновлюємо прогрес
                    processed_size += len(chunk)
                    percentage = (processed_size / file_size) * 100
                    print_progress(percentage)

                # Додаємо фінальні байти
                decryptor.finalize()
                final_unpadded_data = unpadder.finalize()
                f_out.write(final_unpadded_data)


        finally:
            clear_sensitive_data(self.key)
            clear_sensitive_data(self.password)

# Клас для роботи з RSA (Rivest–Shamir–Adleman)
class RSAFileCipher:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    # Генерація RSA ключів (приватний та публічний)
    def generate_keys(self, private_key_file: str, public_key_file: str):
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,  # Загальне значення для RSA
                key_size=2048,  # Розмір ключа (2048 біт)
            )
            self.public_key = self.private_key.public_key()  # Витягуємо публічний ключ

            # Зберігаємо приватний ключ у файл
            with open(private_key_file, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,  # Формат PEM
                    format=serialization.PrivateFormat.PKCS8,  # Формат PKCS8
                    encryption_algorithm=serialization.NoEncryption()  # Без шифрування
                ))

            # Зберігаємо публічний ключ у файл
            with open(public_key_file, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            print(f"Ключі збережено у файли: {private_key_file} та {public_key_file}")
        finally:
            # Очищуємо пам'ять від ключів
            clear_sensitive_data(self.private_key)
            clear_sensitive_data(self.public_key)

    # Шифрування файлу за допомогою RSA
    def encrypt_file(self, input_file: str, output_file: str, public_key_file: str):
        try:
            with open(public_key_file, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())  # Завантажуємо публічний ключ

            with open(input_file, "rb") as f:
                data = f.read()  # Читаємо вхідний файл

            # Шифруємо дані за допомогою RSA-OAEP
            encrypted_data = public_key.encrypt(
                data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),  # Захист через MGF1
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Зберігаємо зашифровані дані у файл
            with open(output_file, "wb") as f:
                f.write(encrypted_data)

            print(f"Файл '{input_file}' зашифровано і збережено як '{output_file}'.")
        except Exception as e:
            print(f"\nПомилка шифрування файлу: {e}")
            print("Спробуйте ще раз, перевіривши вхідні дані та ключі.")
            time.sleep(10)  # Затримка у 10 секунд перед поверненням
        finally:
            # Очищуємо пам'ять від чутливих даних
            clear_sensitive_data(data)
            clear_sensitive_data(encrypted_data)
            clear_sensitive_data(self.public_key)
            clear_sensitive_data(self.private_key)

    def decrypt_file(self, encrypted_file: str, output_file: str, private_key_file: str):
        try:
            # Завантажуємо приватний ключ із файлу
            with open(private_key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            # Зчитуємо зашифрований файл
            with open(encrypted_file, "rb") as f:
                encrypted_data = f.read()

            # Розшифровуємо дані за допомогою RSA-OAEP
            decrypted_data = private_key.decrypt(
                encrypted_data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),  # Захист через MGF1
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Зберігаємо розшифровані дані у вихідний файл
            with open(output_file, "wb") as f:
                f.write(decrypted_data)

            print(f"Файл '{encrypted_file}' розшифровано і збережено як '{output_file}'.")
        finally:
            # Очищуємо пам'ять від чутливих даних
            clear_sensitive_data(encrypted_data)
            clear_sensitive_data(decrypted_data)
            clear_sensitive_data(self.private_key)

    # Метод для підписання файлу за допомогою RSA приватного ключа
    def sign_file(self, input_file: str, signature_file: str, private_key_file: str):
        try:
            # Завантажуємо приватний ключ із вказаного файлу
            with open(private_key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            # Зчитуємо вхідний файл, який потрібно підписати
            with open(input_file, "rb") as f:
                data = f.read()

            # Генеруємо цифровий підпис для даних
            signature = private_key.sign(
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),  # Захист через MGF1
                    salt_length=asym_padding.PSS.MAX_LENGTH  # Максимальна довжина salt
                ),
                hashes.SHA256()  # Хешування даних перед підписанням
            )

            # Зберігаємо підпис у файл
            with open(signature_file, "wb") as f:
                f.write(signature)

            print(f"Файл підписано. Підпис збережено у '{signature_file}'.")
        finally:
            # Очищуємо пам'ять від чутливих даних
            clear_sensitive_data(data)
            clear_sensitive_data(signature)
            clear_sensitive_data(self.private_key)

    # Метод для перевірки цифрового підпису файлу за допомогою RSA публічного ключа
    def verify_signature(self, input_file: str, signature_file: str, public_key_file: str):
        try:
            # Завантажуємо публічний ключ із вказаного файлу
            with open(public_key_file, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            # Зчитуємо вхідний файл, підпис якого потрібно перевірити
            with open(input_file, "rb") as f:
                data = f.read()

            # Зчитуємо цифровий підпис із відповідного файлу
            with open(signature_file, "rb") as f:
                signature = f.read()

            # Перевіряємо підпис
            public_key.verify(
                signature,  # Цифровий підпис
                data,  # Оригінальні дані
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),  # Захист через MGF1
                    salt_length=asym_padding.PSS.MAX_LENGTH  # Максимальна довжина salt
                ),
                hashes.SHA256()  # Хешування даних перед перевіркою
            )
            print("Підпис успішно перевірено.")
        except Exception:
            print("Помилка перевірки підпису! Дані можуть бути змінені.")
        finally:
            # Очищуємо пам'ять від чутливих даних
            clear_sensitive_data(data)
            clear_sensitive_data(signature)

def get_valid_path(prompt: str, must_exist: bool = True) -> str:
    while True:
        path = input(prompt)
        if path.lower() == 'exit':
            return None
        if must_exist and not os.path.exists(path):
            print("Файл не знайдено. Спробуйте ще раз.")
            continue
        return path

def aes_interface():
    while True:
        print("\n====== AES Інтерфейс ======")
        print("1. Шифрування файлу")
        print("2. Дешифрування файлу")
        print("3. Вихід до головного меню")

        choice = input("Ваш вибір: ")

        if choice == "1":
            while True:
                input_file = get_valid_path("Введіть шлях до вхідного файлу (або 'exit' для виходу): ")
                if not input_file:
                    break

                output_file = get_valid_path("Введіть шлях для збереження зашифрованого файлу (або 'exit' для виходу): ")
                if not output_file:
                    break

                try:
                    password = getpass("Введіть пароль:")
                    aes_cipher = AESFileCipher(password=password)
                    aes_cipher.encrypt_file(input_file, output_file)
                    print("\nФайл успішно зашифровано!")
                except Exception as e:
                    print(f"\nПомилка: {e}")
                break
        elif choice == "2":
            while True:
                encrypted_file = get_valid_path("Введіть шлях до зашифрованого файлу (або 'exit' для виходу): ")
                if not encrypted_file:
                    break

                output_file = get_valid_path("Введіть шлях для збереження дешифрованого файлу (або 'exit' для виходу): ")
                if not output_file:
                    break

                try:
                    password = getpass("Введіть пароль:")
                    aes_cipher = AESFileCipher(password=password)
                    aes_cipher.decrypt_file(encrypted_file, output_file)
                    print("\nФайл успішно дешифровано!")
                except Exception as e:
                    print(f"\nПомилка: {e}")
                break
        elif choice == "3":
            print("Повернення до головного меню.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")



def rsa_interface():
    rsa_cipher = RSAFileCipher()

    while True:
        print("\n====== RSA Інтерфейс ======")
        print("1. Генерація RSA ключів")
        print("2. Шифрування файлу (RSA)")
        print("3. Дешифрування файлу (RSA)")
        print("4. Підписання файлу (RSA)")
        print("5. Перевірка підпису (RSA)")
        print("6. Вихід до головного меню")

        choice = input("Ваш вибір: ")

        if choice == "1":
            private_key_file = get_valid_path("Введіть шлях для збереження приватного ключа (або 'exit' для виходу): ")
            if not private_key_file:
                break

            public_key_file = get_valid_path("Введіть шлях для збереження публічного ключа (або 'exit' для виходу): ")
            if not public_key_file:
                break
            try:
                rsa_cipher.generate_keys(private_key_file, public_key_file)
            except Exception as e:
                print(f"\nПомилка: {e}")
        elif choice == "2":
            while True:
                input_file = get_valid_path("Введіть шлях до вхідного файлу (або 'exit' для виходу): ")
                if not input_file:
                    break

                output_file = get_valid_path("Введіть шлях для збереження зашифрованого файлу (або 'exit' для виходу): ")
                if not output_file:
                    break
                public_key_file = get_valid_path("Введіть шлях до публічного ключа (або 'exit' для виходу): ")
                if not public_key_file:
                    break
                try:
                    rsa_cipher.encrypt_file(input_file, output_file, public_key_file)
                except Exception as e:
                    print(f"\nПомилка: {e}")
                break
        elif choice == "3":
            while True:
                encrypted_file = get_valid_path("Введіть шлях до зашифрованого файлу (або 'exit' для виходу): ")
                if not encrypted_file:
                    break

                output_file = get_valid_path("Введіть шлях для збереження дешифрованого файлу (або 'exit' для виходу): ")
                if not output_file:
                    break
                private_key_file = get_valid_path("Введіть шлях до приватного ключа (або 'exit' для виходу): ")
                if not private_key_file:
                    break
                try:
                    rsa_cipher.decrypt_file(encrypted_file, output_file, private_key_file)
                except Exception as e:
                    print(f"\nПомилка: {e}")
                break
        elif choice == "4":
            while True:
                input_file = get_valid_path("Введіть шлях до вхідного файлу (або 'exit' для виходу): ")
                if not input_file:
                    break
                signature_file = get_valid_path("Введіть шлях для збереження підпису (або 'exit' для виходу): ")
                if not signature_file:
                    break
                private_key_file = get_valid_path("Введіть шлях до приватного ключа (або 'exit' для виходу): ")
                if not private_key_file:
                    break
                try:
                    rsa_cipher.sign_file(input_file, signature_file, private_key_file)
                except Exception as e:
                    print(f"\nПомилка: {e}")
                break
        elif choice == "5":
            while True:
                input_file = get_valid_path("Введіть шлях до вхідного файлу (або 'exit' для виходу): ")
                if not input_file:
                    break
                signature_file = get_valid_path("Введіть шлях до файлу з підписом (або 'exit' для виходу): ")
                if not signature_file:
                    break

                public_key_file = get_valid_path("Введіть шлях до публічного ключа (або 'exit' для виходу): ")
                if not public_key_file:
                    break
                try:
                    rsa_cipher.verify_signature(input_file, signature_file, public_key_file)
                except Exception as e:
                    print(f"\nПомилка: {e}")
                break
        elif choice == "6":
            print("Повернення до головного меню.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")



def main():
    while True:
        print("\n====== Головне меню програми шифрування файлів за допомогою AES/RSA ======")
        print("1. AES Інтерфейс")
        print("2. RSA Інтерфейс")
        print("3. Вихід")

        choice = input("Ваш вибір: ")

        if choice == "1":
            aes_interface()
        elif choice == "2":
            rsa_interface()
        elif choice == "3":
            print("Завершення програми.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")


if __name__ == "__main__":
    main()
import tkinter as tk
from tkinter import ttk, messagebox


def stream_cipher_encrypt_decrypt(data: bytes, key: bytes) -> bytes:

    # Генератор псевдослучайных чисел (используется ключ для начальной установки)
    key_stream = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        key_stream.append(key[i % key_len])
    # Шифрование/дешифрование с использованием XOR
    return bytes([data[i] ^ key_stream[i] for i in range(len(data))])

def encrypt_text():
    plaintext = input_text.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not plaintext:
        messagebox.showerror("Ошибка", "Введите текст для шифрования!")
        return

    if not key:
        messagebox.showerror("Ошибка", "Введите ключ шифрования!")
        return

    try:
        encrypted = stream_cipher_encrypt_decrypt(plaintext.encode(), key.encode())
        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", encrypted.hex())  # Отображаем в виде hex
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")


def decrypt_text():
    ciphertext = input_text.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not ciphertext:
        messagebox.showerror("Ошибка", "Введите текст для дешифрования!")
        return

    if not key:
        messagebox.showerror("Ошибка", "Введите ключ шифрования!")
        return

    try:
        encrypted_bytes = bytes.fromhex(ciphertext)  # Преобразуем hex в байты
        decrypted = stream_cipher_encrypt_decrypt(encrypted_bytes, key.encode())
        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", decrypted.decode(errors="ignore"))
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")

# Создаем главное окно
root = tk.Tk()
root.title("Потоковое шифрование")
root.geometry("600x400")

# Поле ввода текста
input_label = ttk.Label(root, text="Введите текст:")
input_label.pack(pady=5)
input_text = tk.Text(root, height=5, width=60)
input_text.pack(pady=5)

# Поле ввода ключа
key_label = ttk.Label(root, text="Введите ключ:")
key_label.pack(pady=5)
key_entry = ttk.Entry(root, width=30)  # Ключ отображается звездочками
key_entry.pack(pady=5)

# Кнопки шифрования и дешифрования
button_frame = ttk.Frame(root)
button_frame.pack(pady=10)

encrypt_button = ttk.Button(button_frame, text="Зашифровать", command=encrypt_text)
encrypt_button.pack(side=tk.LEFT, padx=5)

decrypt_button = ttk.Button(button_frame, text="Расшифровать", command=decrypt_text)
decrypt_button.pack(side=tk.LEFT, padx=5)

# Поле для вывода результата
output_label = ttk.Label(root, text="Результат:")
output_label.pack(pady=5)
output_text = tk.Text(root, height=5, width=60, state=tk.NORMAL)
output_text.pack(pady=5)

# Запуск приложения
root.mainloop()
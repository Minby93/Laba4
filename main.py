import tkinter as tk
from tkinter import ttk, messagebox

# S-блоки ГОСТ 28147-89
S_BOX = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 14, 3, 11, 6, 8, 12],
]

def substitute(value: int) -> int:
    result = 0
    for i in range(8):
        s_block = S_BOX[i][(value >> (4 * i)) & 0xF]
        result |= s_block << (4 * i)
    return result

def rol(value: int, shift: int) -> int:
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

def gost_round(left: int, right: int, key: int) -> (int, int):
    temp = (left + key) % (2 ** 32)
    temp = substitute(temp)
    temp = rol(temp, 11)
    new_right = right ^ temp
    return new_right, left

def pad(data: bytes) -> bytes:
    padding_len = 8 - (len(data) % 8)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]

def gost_encrypt_block(block: bytes, key: bytes) -> bytes:
    left = int.from_bytes(block[:4], byteorder='little')
    right = int.from_bytes(block[4:], byteorder='little')
    key_parts = [int.from_bytes(key[i:i+4], byteorder='little') for i in range(0, 32, 4)]
    for i in range(24):
        right, left = gost_round(left, right, key_parts[i % 8])
    for i in range(8):
        right, left = gost_round(left, right, key_parts[7 - i])
    return left.to_bytes(4, byteorder='little') + right.to_bytes(4, byteorder='little')

def gost_decrypt_block(block: bytes, key: bytes) -> bytes:
    left = int.from_bytes(block[:4], byteorder='little')
    right = int.from_bytes(block[4:], byteorder='little')
    key_parts = [int.from_bytes(key[i:i+4], byteorder='little') for i in range(0, 32, 4)]
    for i in range(8):
        right, left = gost_round(left, right, key_parts[i])
    for i in range(24):
        right, left = gost_round(left, right, key_parts[7 - (i % 8)])
    return left.to_bytes(4, byteorder='little') + right.to_bytes(4, byteorder='little')

def gost_encrypt_message(message: bytes, key: bytes) -> bytes:
    message = pad(message)
    encrypted_message = b''
    for i in range(0, len(message), 8):
        block = message[i:i+8]
        encrypted_message += gost_encrypt_block(block, key)
    return encrypted_message

def gost_decrypt_message(encrypted_message: bytes, key: bytes) -> bytes:
    decrypted_message = b''
    for i in range(0, len(encrypted_message), 8):
        block = encrypted_message[i:i+8]
        decrypted_message += gost_decrypt_block(block, key)
    return unpad(decrypted_message)


def stream_cipher_encrypt_decrypt(data: bytes, key: bytes) -> bytes:

    # Генератор псевдослучайных чисел (используется ключ для начальной установки)
    key_stream = bytearray()
    counter = 0
    while len(key_stream) < len(data):
        counter += 1
        key_stream.extend(gost_encrypt_message(counter.to_bytes(8, byteorder='little'), key))
    # Шифрование/дешифрование с использованием XOR
    key_stream[:len(data)]
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

    #try:
    encrypted = stream_cipher_encrypt_decrypt(plaintext.encode(), key.encode())
    output_text.delete("1.0", tk.END)
    output_text.insert("1.0", encrypted.hex())  # Отображаем в виде hex
    # except Exception as e:
    #     messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")


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
import tkinter as tk
from logging import ERROR
from tkinter import messagebox
import base64
import os
import json

class SimpleEncryptor:
    def __init__(self, key):
        self.key = key

    def encrypt(self, text):
        result = []
        for i, c in enumerate(text):
            result.append(chr(ord(c) ^ ord(self.key[i % len(self.key)])))
        return base64.urlsafe_b64encode("".join(result).encode()).decode()

    def decrypt(self, encrypted_text):
        try:
            text = base64.urlsafe_b64decode(encrypted_text.encode()).decode()
            result = []
            for i, c in enumerate(text):
                result.append(chr(ord(c) ^ ord(self.key[i % len(self.key)])))
            return "".join(result)
        except Exception:
            return ERROR


class PasswordManager:
    def __init__(self, encryptor, file_path="passwords.txt"):
        self.encryptor = encryptor
        self.file_path = file_path
        self.entries = self.load_entries()

    def add(self, site, username, password):
        encrypted = self.encryptor.encrypt(password)
        self.entries.append({
            'site': site,
            'username': username,
            'password': encrypted
        })
        self.save_entries()

    def get_all(self):
        return self.entries

    def save_entries(self):
        with open(self.file_path, "w") as f:
            json.dump(self.entries, f)

    def load_entries(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, "r") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return []
        return []

class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("500x450")

        self.login_screen()

    def login_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Въведи криптиращ ключ:").pack(pady=10)
        self.key_entry = tk.Entry(self.root, show="*")
        self.key_entry.pack(pady=5)

        tk.Button(self.root, text="Вход", command=self.enter_app).pack(pady=10)

    def enter_app(self):
        key = self.key_entry.get()
        if not key:
            messagebox.showwarning("Внимание", "Ключът не може да е празен!")
            return

        self.encryptor = SimpleEncryptor(key)
        self.manager = PasswordManager(self.encryptor)
        self.build_main_ui()

    def build_main_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Сайт").pack()
        self.site_entry = tk.Entry(self.root)
        self.site_entry.pack()
        tk.Label(self.root, text="Потребител").pack()
        self.user_entry = tk.Entry(self.root)
        self.user_entry.pack()
        tk.Label(self.root, text="Парола").pack()
        self.pass_entry = tk.Entry(self.root, show="*")
        self.pass_entry.pack()
        tk.Button(self.root, text="Добави", command=self.add_password).pack(pady=5)
        self.textbox = tk.Text(self.root, height=15)
        self.textbox.pack(pady=10)
        tk.Button(self.root, text="Обнови списъка", command=self.refresh_list).pack()

        self.refresh_list()

    def add_password(self):
        site = self.site_entry.get()
        user = self.user_entry.get()
        password = self.pass_entry.get()

        if site and user and password:
            self.manager.add(site, user, password)
            self.site_entry.delete(0, 'end')
            self.user_entry.delete(0, 'end')
            self.pass_entry.delete(0, 'end')
            self.refresh_list()
        else:
            messagebox.showwarning("Внимание", "Моля, попълни всички полета!")

    def refresh_list(self):
        self.textbox.delete(1.0, tk.END)
        for i, entry in enumerate(self.manager.get_all(), 1):
            decrypted = self.manager.encryptor.decrypt(entry['password'])
            line = f"{i}. {entry['site']} | {entry['username']} | {decrypted}\n"
            self.textbox.insert(tk.END, line)


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop()

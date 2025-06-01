import os
import json
import base64
import getpass
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# -----------------------------------------------------------------------------
# Constantes
# -----------------------------------------------------------------------------
data_file = 'data.enc'
salt_size = 16       # 16 octets pour le sel
iterations = 100_000  # Nombre d'itérations pour PBKDF2

# -----------------------------------------------------------------------------
# Fonctions de chiffrement / déchiffrement
# -----------------------------------------------------------------------------
def derive_key(password: bytes, salt: bytes) -> bytes:
    """Dérive une clé 32 octets à partir du mot de passe et du sel."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def initialize_data(password: bytes) -> (list, bytes):
    """Crée un nouveau fichier de données chiffré (sel + blob vide)."""
    salt = os.urandom(salt_size)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    empty_data = []  # Liste vide d'entrées
    token = fernet.encrypt(json.dumps(empty_data).encode())

    with open(data_file, 'wb') as f:
        f.write(salt + token)
    return empty_data, salt


def load_data(password: bytes) -> (list, bytes):
    """Lit 'data.enc', extrait le sel, dérive la clé, puis déchiffre le JSON."""
    with open(data_file, 'rb') as f:
        raw = f.read()

    salt = raw[:salt_size]
    token = raw[salt_size:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(token)
        data = json.loads(decrypted.decode())
    except Exception:
        raise ValueError("Mot de passe incorrect ou fichier corrompu.")

    return data, salt


def save_data(data: list, password: bytes, salt: bytes) -> None:
    """Chiffre à nouveau la structure de données et sauve 'salt + blob'."""
    key = derive_key(password, salt)
    fernet = Fernet(key)
    token = fernet.encrypt(json.dumps(data).encode())
    with open(data_file, 'wb') as f:
        f.write(salt + token)

# -----------------------------------------------------------------------------
# Classe principale de l'application
# -----------------------------------------------------------------------------
class SecureDataStoreApp:
    def __init__(self, root):
        self.root = root
        self.root.withdraw()  # Masquer la fenêtre principale jusqu'à authentification
        self.data = []
        self.salt = None
        self.master_password = None

        if not os.path.exists(data_file):
            self.setup_master_password()
        else:
            self.prompt_master_password()

    def setup_master_password(self):
        """Invite l'utilisateur à créer un nouveau mot de passe maître."""
        pwd = simpledialog.askstring("Initialisation", "Choisissez un mot de passe maître:", show="*")
        if not pwd:
            self.root.destroy()
            return
        self.master_password = pwd.encode()
        self.data, self.salt = initialize_data(self.master_password)
        messagebox.showinfo("Initialisation", "Fichier initialisé. Veuillez relancer l'application.")
        self.root.destroy()

    def prompt_master_password(self):
        """Invite l'utilisateur à entrer le mot de passe pour déchiffrer les données."""
        pwd = simpledialog.askstring("Connexion", "Entrez votre mot de passe maître:", show="*")
        if not pwd:
            self.root.destroy()
            return
        try:
            self.data, self.salt = load_data(pwd.encode())
            self.master_password = pwd.encode()
            self.show_main_window()
        except ValueError as e:
            messagebox.showerror("Erreur", str(e))
            self.root.destroy()

    def show_main_window(self):
        """Construit et affiche la fenêtre principale après authentification."""
        self.root.deiconify()
        self.root.title("Gestionnaire d'identités sécurisé")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Liste des entrées
        self.entries_listbox = tk.Listbox(main_frame, height=15)
        self.entries_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.entries_listbox.bind('<Double-Button-1>', lambda e: self.view_entry())

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.entries_listbox.yview)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        self.entries_listbox.config(yscrollcommand=scrollbar.set)

        # Boutons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))

        ttk.Button(button_frame, text="Ajouter", width=15, command=self.add_entry).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Voir", width=15, command=self.view_entry).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Supprimer", width=15, command=self.delete_entry).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Quitter", width=15, command=self.quit_app).pack(pady=(0, 10))

        self.refresh_entries_list()

    def refresh_entries_list(self):
        """Recharge la Listbox avec les libellés actuels."""
        self.entries_listbox.delete(0, tk.END)
        for entry in self.data:
            self.entries_listbox.insert(tk.END, entry.get('label', ''))

    def add_entry(self):
        """Ouvre une fenêtre pour ajouter une nouvelle entrée."""
        entry_window = tk.Toplevel(self.root)
        entry_window.title("Ajouter une entrée")
        entry_window.geometry("350x300")
        entry_window.resizable(False, False)

        fields = ['Libellé', 'Email', 'YouTube', 'TikTok', 'Instagram', 'Notes']
        entries_vars = {}

        for idx, field in enumerate(fields):
            ttk.Label(entry_window, text=field).grid(row=idx, column=0, pady=5, sticky=tk.W)
            var = tk.StringVar()
            ttk.Entry(entry_window, textvariable=var, width=30).grid(row=idx, column=1, pady=5)
            entries_vars[field.lower()] = var

        def save_new_entry():
            new_entry = {
                'label': entries_vars['libellé'].get().strip(),
                'email': entries_vars['email'].get().strip(),
                'youtube': entries_vars['youtube'].get().strip(),
                'tiktok': entries_vars['tiktok'].get().strip(),
                'instagram': entries_vars['instagram'].get().strip(),
                'notes': entries_vars['notes'].get().strip(),
            }
            if not new_entry['label']:
                messagebox.showwarning("Champs manquants", "Le libellé est obligatoire.")
                return
            self.data.append(new_entry)
            save_data(self.data, self.master_password, self.salt)
            self.refresh_entries_list()
            entry_window.destroy()

        ttk.Button(entry_window, text="Enregistrer", command=save_new_entry).grid(row=len(fields), column=0, columnspan=2, pady=10)

    def view_entry(self):
        """Affiche une fenêtre avec les détails de l'entrée sélectionnée."""
        selection = self.entries_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        entry = self.data[idx]

        view_window = tk.Toplevel(self.root)
        view_window.title(f"Détails - {entry.get('label', '')}")
        view_window.geometry("350x300")
        view_window.resizable(False, False)

        fields = {
            'Libellé': entry.get('label', ''),
            'Email': entry.get('email', ''),
            'YouTube': entry.get('youtube', ''),
            'TikTok': entry.get('tiktok', ''),
            'Instagram': entry.get('instagram', ''),
            'Notes': entry.get('notes', ''),
        }

        for idx, (field, value) in enumerate(fields.items()):
            ttk.Label(view_window, text=f"{field}:", font=('Segoe UI', 10, 'bold')).grid(row=idx, column=0, pady=5, sticky=tk.W)
            ttk.Label(view_window, text=value, wraplength=250).grid(row=idx, column=1, pady=5, sticky=tk.W)

        ttk.Button(view_window, text="Fermer", command=view_window.destroy).grid(row=len(fields), column=0, columnspan=2, pady=10)

    def delete_entry(self):
        """Supprime l'entrée sélectionnée après confirmation."""
        selection = self.entries_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        entry = self.data[idx]
        answer = messagebox.askyesno("Confirmation", f"Supprimer '{entry.get('label', '')}' ?")
        if answer:
            self.data.pop(idx)
            save_data(self.data, self.master_password, self.salt)
            self.refresh_entries_list()

    def quit_app(self):
        """Enregistre les données et quitte proprement."""
        save_data(self.data, self.master_password, self.salt)
        self.root.destroy()

# -----------------------------------------------------------------------------
# Point d'entrée
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    root = tk.Tk()
    app = SecureDataStoreApp(root)
    root.mainloop()

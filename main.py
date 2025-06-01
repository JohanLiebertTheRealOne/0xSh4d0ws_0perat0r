import os
import json
import base64
import secrets
import string
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import logging
import importlib.util
import sys

# -----------------------------------------------------------------------------
# Logger configuration for real-time monitoring
# -----------------------------------------------------------------------------
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
data_file = 'data.enc'
salt_size = 16             # 16 bytes for salt
kdf_n = 2 ** 14            # Scrypt parameter N (cost)
kdf_r = 8                  # Scrypt parameter r
kdf_p = 1                  # Scrypt parameter p
inactivity_timeout = 300   # seconds before auto-lock (5 minutes)
max_attempts = 5           # max password attempts
plugins_folder = 'plugins' # folder for external modules

# -----------------------------------------------------------------------------
# Encryption/Decryption functions using Scrypt
# -----------------------------------------------------------------------------
def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte key from password and salt using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=kdf_n,
        r=kdf_r,
        p=kdf_p,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def initialize_data(password: bytes) -> (list, bytes):
    """Create a new encrypted data file (salt + encrypted empty JSON)."""
    salt = os.urandom(salt_size)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    empty_data = []  # empty list of entries
    token = fernet.encrypt(json.dumps(empty_data).encode())

    with open(data_file, 'wb') as f:
        f.write(salt + token)
    logging.info('Initialized data.enc with new salt.')
    return empty_data, salt


def load_data(password: bytes) -> (list, bytes):
    """Read 'data.enc', extract salt, derive key, then decrypt JSON."""
    if not os.path.exists(data_file):
        raise ValueError("Data file not found. Please initialize first.")
    with open(data_file, 'rb') as f:
        raw = f.read()
    if len(raw) < salt_size:
        raise ValueError("Data file corrupted or invalid.")

    salt = raw[:salt_size]
    token = raw[salt_size:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(token)
        data = json.loads(decrypted.decode())
        logging.info('Data loaded successfully.')
    except Exception:
        logging.warning('Decryption failed: incorrect password or corrupted file.')
        raise ValueError("Incorrect password or corrupted data file.")

    return data, salt


def save_data(data: list, password: bytes, salt: bytes) -> None:
    """Encrypt data and save 'salt + encrypted blob'."""
    key = derive_key(password, salt)
    fernet = Fernet(key)
    token = fernet.encrypt(json.dumps(data).encode())
    with open(data_file, 'wb') as f:
        f.write(salt + token)
    logging.info('Data saved successfully.')

# -----------------------------------------------------------------------------
# Secret generators
# -----------------------------------------------------------------------------
def generate_password(length: int = 16) -> str:
    """Generate a random password with letters, digits, and symbols."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Lists for human-readable passphrase generation
def get_passphrase_components():
    adjectives = [
        'orange', 'fat', 'blue', 'swift', 'silent', 'happy', 'brave', 'ancient', 'fierce', 'gentle',
        'wild', 'shy', 'mighty', 'tiny', 'proud', 'calm', 'bold', 'curious', 'eager', 'frozen'
    ]
    nouns = [
        'fox', 'frog', 'eagle', 'tiger', 'elephant', 'lion', 'wolf', 'dolphin', 'whale', 'dragon',
        'raven', 'panda', 'otter', 'hawk', 'bear', 'rabbit', 'shark', 'falcon', 'leopard', 'giraffe'
    ]
    verbs = [
        'jumps', 'runs', 'flies', 'dives', 'sprints', 'leaps', 'soars', 'dances', 'glides', 'charges',
        'dashes', 'trots', 'rockets', 'slides', 'bounds', 'creeps', 'prowls', 'marches', 'floats'
    ]
    prepositions = ['over', 'across', 'beyond', 'among', 'through', 'above', 'around']
    return adjectives, nouns, verbs, prepositions


def generate_passphrase() -> str:
    """Generate a unique passphrase, e.g.: "The orange fox jumps over the fat blue frog"."""
    adjectives, nouns, verbs, prepositions = get_passphrase_components()
    adj1 = secrets.choice(adjectives)
    noun1 = secrets.choice(nouns)
    verb = secrets.choice(verbs)
    prep = secrets.choice(prepositions)
    adj2 = secrets.choice(adjectives)
    adj3 = secrets.choice(adjectives)
    noun2 = secrets.choice(nouns)
    return f"The {adj1} {noun1} {verb} {prep} the {adj2} {adj3} {noun2}"

# -----------------------------------------------------------------------------
# Plugin handling
# -----------------------------------------------------------------------------
def load_plugins():
    """Dynamically load Python plugins from 'plugins' folder."""
    plugins = {}
    if not os.path.isdir(plugins_folder):
        os.makedirs(plugins_folder)
        return plugins

    for fname in os.listdir(plugins_folder):
        if fname.endswith('.py'):
            path = os.path.join(plugins_folder, fname)
            spec = importlib.util.spec_from_file_location(fname[:-3], path)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                if hasattr(module, 'Plugin'):
                    plugins[fname[:-3]] = module.Plugin()
                    logging.info(f"Plugin loaded: {fname}")
            except Exception as e:
                logging.error(f"Failed to load plugin {fname}: {e}")
    return plugins

# -----------------------------------------------------------------------------
# Main application class
# -----------------------------------------------------------------------------
class SecureDataStoreApp:
    def __init__(self, root):
        self.root = root
        self.data = []
        self.salt = None
        self.master_password = None
        self.attempts = 0
        self.inactivity_timer = None
        self.plugins = load_plugins()

        # If data file doesn't exist, run initialization before mainloop
        if not os.path.exists(data_file):
            self.first_time_setup()
        else:
            self.setup_authentication()

    def first_time_setup(self):
        """Initialization routine before showing the GUI."""
        self.root.withdraw()
        use_passphrase = messagebox.askyesno(
            "Initialization - Master Key", 
            "Would you like to generate a unique passphrase as the master key?"
        )
        if use_passphrase:
            passphrase = generate_passphrase()
            self.root.clipboard_clear()
            self.root.clipboard_append(passphrase)
            messagebox.showinfo(
                "Passphrase Generated",
                f"Your unique passphrase is:\n\n{passphrase}\n\n(It has been copied to the clipboard.)"
            )
            pwd = passphrase
        else:
            pwd = simpledialog.askstring(
                "Initialization - Master Key",
                "Enter a master password (min 12 characters):",
                show="*"
            )
            if not pwd or len(pwd) < 12:
                messagebox.showwarning("Weak Password", "A password of at least 12 characters is required.")
                self.root.destroy()
                return

        self.master_password = pwd.encode()
        self.data, self.salt = initialize_data(self.master_password)
        messagebox.showinfo("Initialization Complete", "Data file initialized. Please restart the application.")
        self.root.destroy()

    def setup_authentication(self):
        """Prepare GUI for login phase."""
        self.root.withdraw()
        self.prompt_master_password()

    def reset_inactivity_timer(self):
        """Reset the inactivity timer."""
        if self.inactivity_timer:
            self.inactivity_timer.cancel()
        self.inactivity_timer = threading.Timer(inactivity_timeout, self.lock_due_inactivity)
        self.inactivity_timer.daemon = True
        self.inactivity_timer.start()

    def lock_due_inactivity(self):
        """Lock the application after inactivity."""
        messagebox.showinfo("Locked", "Automatically locked for security.")
        self.root.withdraw()
        self.prompt_master_password()

    def prompt_master_password(self):
        """Prompt user to enter the master password or passphrase."""
        if self.attempts >= max_attempts:
            messagebox.showerror("Access Denied", "Too many failed attempts. Exiting.")
            self.root.destroy()
            return

        pwd = simpledialog.askstring("Login", "Enter your master password or passphrase:", show="*")
        if not pwd:
            self.root.destroy()
            return
        try:
            self.data, self.salt = load_data(pwd.encode())
            self.master_password = pwd.encode()
            self.attempts = 0
            self.show_main_window()
        except ValueError as e:
            self.attempts += 1
            messagebox.showerror("Error", f"{str(e)} ({self.attempts}/{max_attempts})")
            self.prompt_master_password()

    def show_main_window(self):
        """Build and display the main application window."""
        self.root.deiconify()
        self.root.title("Secure Identity Manager")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        # Main menu
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        plugin_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Plugins", menu=plugin_menu)
        if self.plugins:
            for name, plugin in self.plugins.items():
                plugin_menu.add_command(
                    label=name,
                    command=lambda p=plugin: self.run_plugin(p)
                )
        else:
            plugin_menu.add_command(label="No plugins found", state=tk.DISABLED)

        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Search bar
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X)
        self.search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(search_frame, text="Search", command=self.search_entries).pack(side=tk.LEFT)
        ttk.Button(search_frame, text="Reset", command=self.refresh_entries_list).pack(side=tk.LEFT, padx=(5, 0))

        # Listbox of entries
        self.entries_listbox = tk.Listbox(main_frame, height=15)
        self.entries_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=(10, 0))
        self.entries_listbox.bind('<Double-Button-1>', lambda e: self.view_entry())

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.entries_listbox.yview)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=(10, 0))
        self.entries_listbox.config(yscrollcommand=scrollbar.set)

        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0), pady=(10, 0))
        ttk.Button(button_frame, text="Add", width=15, command=self.add_entry).pack(pady=(0, 10))
        ttk.Button(button_frame, text="View", width=15, command=self.view_entry).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Delete", width=15, command=self.delete_entry).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Generate Password", width=15, command=self.show_password_generator).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Quit", width=15, command=self.quit_app).pack(pady=(0, 10))

        self.refresh_entries_list()
        self.reset_inactivity_timer()
        self.root.bind_all("<Any-KeyPress>", lambda e: self.reset_inactivity_timer())
        self.root.bind_all("<Any-Button>", lambda e: self.reset_inactivity_timer())

    def refresh_entries_list(self):
        """Reload the listbox with current labels."""
        self.entries_listbox.delete(0, tk.END)
        for entry in self.data:
            self.entries_listbox.insert(tk.END, entry.get('label', ''))

    def search_entries(self):
        """Filter the list based on the search query."""
        query = self.search_var.get().strip().lower()
        self.entries_listbox.delete(0, tk.END)
        for entry in self.data:
            if query in entry.get('label', '').lower() or query in entry.get('email', '').lower():
                self.entries_listbox.insert(tk.END, entry.get('label', ''))

    def add_entry(self):
        """Open a window to add a new entry."""
        entry_window = tk.Toplevel(self.root)
        entry_window.title("Add Entry")
        entry_window.geometry("400x350")
        entry_window.resizable(False, False)

        fields = ['Label', 'Email', 'YouTube', 'TikTok', 'Instagram', 'Notes']
        entries_vars = {}

        for idx, field in enumerate(fields):
            ttk.Label(entry_window, text=field).grid(row=idx, column=0, pady=5, sticky=tk.W)
            var = tk.StringVar()
            ttk.Entry(entry_window, textvariable=var, width=35).grid(row=idx, column=1, pady=5)
            entries_vars[field.lower()] = var

        def save_new_entry():
            new_entry = {
                'label': entries_vars['label'].get().strip(),
                'email': entries_vars['email'].get().strip(),
                'youtube': entries_vars['youtube'].get().strip(),
                'tiktok': entries_vars['tiktok'].get().strip(),
                'instagram': entries_vars['instagram'].get().strip(),
                'notes': entries_vars['notes'].get().strip(),
            }
            if not new_entry['label']:
                messagebox.showwarning("Missing Field", "Label is required.")
                return
            self.data.append(new_entry)
            save_data(self.data, self.master_password, self.salt)
            self.refresh_entries_list()
            logging.info(f"New entry added: {new_entry['label']}")
            entry_window.destroy()

        ttk.Button(entry_window, text="Save", command=save_new_entry).grid(row=len(fields), column=0, columnspan=2, pady=15)

    def view_entry(self):
        """Display a window with details of the selected entry."""
        selection = self.entries_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        entry = self.data[idx]

        view_window = tk.Toplevel(self.root)
        view_window.title(f"Details - {entry.get('label', '')}")
        view_window.geometry("400x350")
        view_window.resizable(False, False)

        fields = {
            'Label': entry.get('label', ''),
            'Email': entry.get('email', ''),
            'YouTube': entry.get('youtube', ''),
            'TikTok': entry.get('tiktok', ''),
            'Instagram': entry.get('instagram', ''),
            'Notes': entry.get('notes', ''),
        }

        for idx, (field, value) in enumerate(fields.items()):
            ttk.Label(view_window, text=f"{field}:", font=('Segoe UI', 10, 'bold')).grid(row=idx, column=0, pady=5, sticky=tk.W)
            ttk.Label(view_window, text=value, wraplength=300).grid(row=idx, column=1, pady=5, sticky=tk.W)

        ttk.Button(view_window, text="Close", command=view_window.destroy).grid(row=len(fields), column=0, columnspan=2, pady=15)

    def delete_entry(self):
        """Delete the selected entry after confirmation."""
        selection = self.entries_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        entry = self.data[idx]
        answer = messagebox.askyesno("Confirmation", f"Delete '{entry.get('label', '')}'?")
        if answer:
            removed_label = entry.get('label', '')
            self.data.pop(idx)
            save_data(self.data, self.master_password, self.salt)
            self.refresh_entries_list()
            logging.info(f"Entry deleted: {removed_label}")

    def show_password_generator(self):
        """Display a strong password generator and copy to clipboard."""
        length = simpledialog.askinteger("Password Generator", "Password length:", minvalue=8, maxvalue=64)
        if not length:
            return
        pwd = generate_password(length)
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Generated Password", f"{pwd}\n(The password has been copied to the clipboard.)")
        logging.info("Strong password generated and copied.")

    def run_plugin(self, plugin):
        """Run a loaded plugin with its interface."""
        try:
            plugin.run(self)  # pass the app instance for potential interaction
            logging.info(f"Plugin executed: {plugin}")
        except Exception as e:
            logging.error(f"Plugin execution error: {e}")
            messagebox.showerror("Plugin Error", f"An error occurred: {e}")

    def quit_app(self):
        """Save data and exit cleanly."""
        if self.inactivity_timer:
            self.inactivity_timer.cancel()
        save_data(self.data, self.master_password, self.salt)
        logging.info("Application closed.")
        self.root.destroy()

# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    # Basic CLI interface if arguments provided
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'list':
            if not os.path.exists(data_file):
                print("No data file found. Initialize first.")
                sys.exit(0)
            pwd = input("Enter master password or passphrase: ")
            try:
                data, _ = load_data(pwd.encode())
                for entry in data:
                    print(f"- {entry.get('label')} : {entry.get('email')}")
            except Exception as e:
                print(f"Error: {e}")
            sys.exit(0)
        # Additional CLI commands can be added here

    root = tk.Tk()
    app = SecureDataStoreApp(root)
    root.mainloop()
import os
import json
import base64
import secrets
import string
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import logging
import importlib.util
import sys

# -----------------------------------------------------------------------------
# Configuration du logger pour surveillance en temps réel
# -----------------------------------------------------------------------------
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# -----------------------------------------------------------------------------
# Constantes
# -----------------------------------------------------------------------------
data_file = 'data.enc'
salt_size = 16             # 16 octets pour le sel
kdf_n = 2 ** 14            # Paramètre N de Scrypt (coût)
kdf_r = 8                 # Paramètre r de Scrypt
kdf_p = 1                 # Paramètre p de Scrypt
inactivity_timeout = 300   # secondes avant verrouillage automatique (5 minutes)
max_attempts = 5           # Tentatives max de mot de passe
plugins_folder = 'plugins'  # Répertoire pour modules externes

# -----------------------------------------------------------------------------
# Fonctions de chiffrement / déchiffrement avec Scrypt
# -----------------------------------------------------------------------------
def derive_key(password: bytes, salt: bytes) -> bytes:
    """Dérive une clé 32 octets à partir du mot de passe et du sel en utilisant Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=kdf_n,
        r=kdf_r,
        p=kdf_p,
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
    logging.info('Initialisation de data.enc avec nouveau sel.')
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
        logging.info('Chargement des données réussi.')
    except Exception:
        logging.warning('Échec du déchiffrement: mot de passe incorrect ou fichier corrompu.')
        raise ValueError("Mot de passe incorrect ou fichier corrompu.")

    return data, salt


def save_data(data: list, password: bytes, salt: bytes) -> None:
    """Chiffre à nouveau la structure de données et sauve 'salt + blob'."""
    key = derive_key(password, salt)
    fernet = Fernet(key)
    token = fernet.encrypt(json.dumps(data).encode())
    with open(data_file, 'wb') as f:
        f.write(salt + token)
    logging.info('Données sauvegardées.')

# -----------------------------------------------------------------------------
# Générateurs de secrets
# -----------------------------------------------------------------------------
def generate_password(length: int = 16) -> str:
    """Génère un mot de passe aléatoire composé de lettres, chiffres et symboles."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Listes pour générer une passphrase humaine
def get_passphrase_components():
    adjectifs = [
        'orange', 'fat', 'blue', 'swift', 'silent', 'happy', 'brave', 'ancient', 'fierce', 'gentle',
        'wild', 'shy', 'mighty', 'tiny', 'proud', 'calm', 'bold', 'curious', 'eager', 'frozen'
    ]
    noms = [
        'fox', 'frog', 'eagle', 'tiger', 'elephant', 'lion', 'wolf', 'dolphin', 'whale', 'dragon',
        'raven', 'panda', 'otter', 'hawk', 'bear', 'rabbit', 'shark', 'falcon', 'leopard', 'giraffe'
    ]
    verbes = [
        'jumps', 'runs', 'flies', 'dives', 'sprints', 'leaps', 'soars', 'dances', 'glides', 'charges',
        'dashes', 'trots', 'rockets', 'slides', 'bounds', 'creeps', 'prowls', 'marches', 'floats'
    ]
    prepositions = ['over', 'across', 'beyond', 'among', 'through', 'above', 'around']
    return adjectifs, noms, verbes, prepositions


def generate_passphrase() -> str:
    """Génère une phrase de passe unique, ex.: "The orange fox jumps over the fat blue frog"."""
    adjectifs, noms, verbes, prepositions = get_passphrase_components()
    adj1 = secrets.choice(adjectifs)
    noun1 = secrets.choice(noms)
    verb = secrets.choice(verbes)
    prep = secrets.choice(prepositions)
    adj2 = secrets.choice(adjectifs)
    adj3 = secrets.choice(adjectifs)
    noun2 = secrets.choice(noms)
    return f"The {adj1} {noun1} {verb} {prep} the {adj2} {adj3} {noun2}"

# -----------------------------------------------------------------------------
# Gestion des plugins
# -----------------------------------------------------------------------------
def load_plugins():
    """Charge dynamiquement les plugins Python depuis le dossier 'plugins'."""
    plugins = {}
    if not os.path.isdir(plugins_folder):
        os.makedirs(plugins_folder)
        return plugins

    for fname in os.listdir(plugins_folder):
        if fname.endswith('.py'):
            path = os.path.join(plugins_folder, fname)
            spec = importlib.util.spec_from_file_location(fname[:-3], path)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                if hasattr(module, 'Plugin'):
                    plugins[fname[:-3]] = module.Plugin()
                    logging.info(f"Plugin chargé: {fname}")
            except Exception as e:
                logging.error(f"Échec du chargement du plugin {fname}: {e}")
    return plugins

# -----------------------------------------------------------------------------
# Classe principale de l'application
# -----------------------------------------------------------------------------
class SecureDataStoreApp:
    def __init__(self, root):
        self.root = root
        self.data = []
        self.salt = None
        self.master_password = None
        self.attempts = 0
        self.inactivity_timer = None
        self.plugins = load_plugins()

        # Si le fichier n'existe pas : initialisation avant mainloop
        if not os.path.exists(data_file):
            self.first_time_setup()
        else:
            self.setup_authentication()

    def first_time_setup(self):
        """Processus d'initialisation (avant affichage de la GUI)."""
        self.root.withdraw()
        use_passphrase = messagebox.askyesno(
            "Initialisation - Clé maître",
            "Voulez-vous générer une phrase de passe unique comme clé maîtresse ?"
        )
        if use_passphrase:
            passphrase = generate_passphrase()
            self.root.clipboard_clear()
            self.root.clipboard_append(passphrase)
            messagebox.showinfo(
                "Passphrase générée",
                f"Votre phrase de passe unique est :\n\n{passphrase}\n\n(Elle a été copiée dans le presse-papiers.)"
            )
            pwd = passphrase
        else:
            pwd = simpledialog.askstring(
                "Initialisation - Clé maître",
                "Choisissez un mot de passe maître (min 12 caractères):",
                show="*"
            )
            if not pwd or len(pwd) < 12:
                messagebox.showwarning("Mot de passe faible", "Un mot de passe d'au moins 12 caractères est requis.")
                self.root.destroy()
                return

        self.master_password = pwd.encode()
        self.data, self.salt = initialize_data(self.master_password)
        messagebox.showinfo("Initialisation", "Fichier initialisé. Relancez l'application pour continuer.")
        self.root.destroy()

    def setup_authentication(self):
        """Prépare l’interface pour la phase de connexion."""
        self.root.withdraw()
        self.prompt_master_password()

    def reset_inactivity_timer(self):
        """Réinitialise le minuteur d'inactivité."""
        if self.inactivity_timer:
            self.inactivity_timer.cancel()
        self.inactivity_timer = threading.Timer(inactivity_timeout, self.lock_due_inactivity)
        self.inactivity_timer.daemon = True
        self.inactivity_timer.start()

    def lock_due_inactivity(self):
        """Verrouille l'application après inactivité."""
        messagebox.showinfo("Verrouillage", "Verrouillage automatique pour sécurité.")
        self.root.withdraw()
        self.prompt_master_password()

    def prompt_master_password(self):
        """Invite pour saisir le mot de passe maître."""
        if self.attempts >= max_attempts:
            messagebox.showerror("Accès bloqué", "Trop de tentatives échouées. Fermeture de l'application.")
            self.root.destroy()
            return

        pwd = simpledialog.askstring("Connexion", "Entrez votre mot de passe maître:", show="*")
        if not pwd:
            self.root.destroy()
            return
        try:
            self.data, self.salt = load_data(pwd.encode())
            self.master_password = pwd.encode()
            self.attempts = 0
            self.show_main_window()
        except ValueError as e:
            self.attempts += 1
            messagebox.showerror("Erreur", f"{str(e)} ({self.attempts}/{max_attempts})")
            self.prompt_master_password()

    def show_main_window(self):
        """Construction et affichage de la fenêtre principale."""
        self.root.deiconify()
        self.root.title("Gestionnaire d'identités sécurisé")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        # Menu principal
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        # Menu Plugins
        plugin_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Plugins", menu=plugin_menu)
        if self.plugins:
            for name, plugin in self.plugins.items():
                plugin_menu.add_command(
                    label=name,
                    command=lambda p=plugin: self.run_plugin(p)
                )
        else:
            plugin_menu.add_command(label="Aucun plugin trouvé", state=tk.DISABLED)

        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Barre de recherche
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X)
        self.search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(search_frame, text="Rechercher", command=self.search_entries).pack(side=tk.LEFT)
        ttk.Button(search_frame, text="Réinitialiser", command=self.refresh_entries_list).pack(side=tk.LEFT, padx=(5, 0))

        # Listbox des entrées
        self.entries_listbox = tk.Listbox(main_frame, height=15)
        self.entries_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=(10, 0))
        self.entries_listbox.bind('<Double-Button-1>', lambda e: self.view_entry())

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.entries_listbox.yview)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=(10, 0))
        self.entries_listbox.config(yscrollcommand=scrollbar.set)

        # Boutons d’action
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0), pady=(10, 0))
        ttk.Button(button_frame, text="Ajouter", width=15, command=self.add_entry).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Voir", width=15, command=self.view_entry).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Supprimer", width=15, command=self.delete_entry).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Générer MDPC", width=15, command=self.show_password_generator).pack(pady=(0, 10))
        ttk.Button(button_frame, text="Quitter", width=15, command=self.quit_app).pack(pady=(0, 10))

        self.refresh_entries_list()
        self.reset_inactivity_timer()
        self.root.bind_all("<Any-KeyPress>", lambda e: self.reset_inactivity_timer())
        self.root.bind_all("<Any-Button>", lambda e: self.reset_inactivity_timer())

    def refresh_entries_list(self):
        """Recharge la Listbox avec les libellés actuels."""
        self.entries_listbox.delete(0, tk.END)
        for entry in self.data:
            self.entries_listbox.insert(tk.END, entry.get('label', ''))

    def search_entries(self):
        """Filtre la liste en fonction de la chaîne saisie."""
        query = self.search_var.get().strip().lower()
        self.entries_listbox.delete(0, tk.END)
        for entry in self.data:
            if query in entry.get('label', '').lower() or query in entry.get('email', '').lower():
                self.entries_listbox.insert(tk.END, entry.get('label', ''))

    def add_entry(self):
        """Ouvre une fenêtre pour ajouter une nouvelle entrée."""
        entry_window = tk.Toplevel(self.root)
        entry_window.title("Ajouter une entrée")
        entry_window.geometry("400x350")
        entry_window.resizable(False, False)

        fields = ['Libellé', 'Email', 'YouTube', 'TikTok', 'Instagram', 'Notes']
        entries_vars = {}

        for idx, field in enumerate(fields):
            ttk.Label(entry_window, text=field).grid(row=idx, column=0, pady=5, sticky=tk.W)
            var = tk.StringVar()
            ttk.Entry(entry_window, textvariable=var, width=35).grid(row=idx, column=1, pady=5)
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
            logging.info(f"Nouvelle entrée ajoutée : {new_entry['label']}")
            entry_window.destroy()

        ttk.Button(entry_window, text="Enregistrer", command=save_new_entry).grid(row=len(fields), column=0, columnspan=2, pady=15)

    def view_entry(self):
        """Affiche une fenêtre avec les détails de l'entrée sélectionnée."""
        selection = self.entries_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        entry = self.data[idx]

        view_window = tk.Toplevel(self.root)
        view_window.title(f"Détails - {entry.get('label', '')}")
        view_window.geometry("400x350")
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
            ttk.Label(view_window, text=value, wraplength=300).grid(row=idx, column=1, pady=5, sticky=tk.W)

        ttk.Button(view_window, text="Fermer", command=view_window.destroy).grid(row=len(fields), column=0, columnspan=2, pady=15)

    def delete_entry(self):
        """Supprime l'entrée sélectionnée après confirmation."""
        selection = self.entries_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        entry = self.data[idx]
        answer = messagebox.askyesno("Confirmation", f"Supprimer '{entry.get('label', '')}' ?")
        if answer:
            removed_label = entry.get('label', '')
            self.data.pop(idx)
            save_data(self.data, self.master_password, self.salt)
            self.refresh_entries_list()
            logging.info(f"Entrée supprimée : {removed_label}")

    def show_password_generator(self):
        """Affiche un mot de passe fort généré et copie dans le presse-papiers."""
        length = simpledialog.askinteger("Générateur MDPC", "Longueur du mot de passe:", minvalue=8, maxvalue=64)
        if not length:
            return
        pwd = generate_password(length)
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Mot de passe généré", f"{pwd}\n(Le mot de passe a été copié dans le presse-papiers.)")
        logging.info("Mot de passe fort généré et copié.")

    def run_plugin(self, plugin):
        """Exécute un plugin chargé avec son interface."""
        try:
            plugin.run(self)  # On passe l'instance pour interaction éventuelle
            logging.info(f"Plugin exécuté : {plugin}")
        except Exception as e:
            logging.error(f"Erreur lors de l'exécution du plugin: {e}")
            messagebox.showerror("Plugin erreur", f"Une erreur est survenue: {e}")

    def quit_app(self):
        """Enregistre les données et quitte proprement."""
        if self.inactivity_timer:
            self.inactivity_timer.cancel()
        save_data(self.data, self.master_password, self.salt)
        logging.info("Application fermée.")
        self.root.destroy()


# -----------------------------------------------------------------------------
# Exécution principale
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    # Si des arguments en CLI sont passés, on peut ajouter une interface CLI basique
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'list':
            if not os.path.exists(data_file):
                print("Aucun fichier de données trouvé.")
                sys.exit(0)
            pwd = input("Mot de passe maître: ")
            try:
                data, _ = load_data(pwd.encode())
                for entry in data:
                    print(f"- {entry.get('label')} : {entry.get('email')}")
            except Exception as e:
                print(f"Erreur: {e}")
            sys.exit(0)
        # D'autres commandes CLI peuvent être ajoutées ici

    root = tk.Tk()
    app = SecureDataStoreApp(root)
    root.mainloop()
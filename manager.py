import sys, os, json, getopt
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip
from art import tprint
KDF_ALGORITHM = hashes.SHA256()
KDF_LENGTH = 32
KDF_ITERATIONS = 120000


class Data:
    def __init__(self, JSON):
        self.json = JSON
    def hasKeyword(self, keyword):
        if not keyword in self.json["keywords"]:
            print(f"Keyword {keyword} doesn't exist in the DB. Use 'add {keyword} <password>' to add it.")
            return False
        return True
    def hasNoKeyword(self, keyword):
        if keyword in self.json["keywords"]:
            print(f"Keyword {keyword} already exists in the DB. Use 'change {keyword} <password>' to change the entry.")
            return False
        return True
    def add(self, keyword, password):
        if self.hasNoKeyword(keyword):
            self.json["keywords"][keyword] = password
    def change(self, keyword, password):
        if self.hasKeyword(keyword):
            self.json["keywords"][keyword] = password
    def delete(self, keyword):
        if self.hasKeyword(keyword):
            del self.json["keywords"][keyword]
    def list(self):
        print("[*] Printing all keywords in the DB.")
        print('\n'.join(self.json["keywords"].keys()))
    def fetch(self, keyword):
        if self.hasKeyword(keyword):
            pyperclip.copy(self.json["keywords"][keyword])
            pyperclip.paste()
            print("[*] The password has been pasted in your clipboard.")
    def show(self, keyword):
        if self.hasKeyword(keyword):
            print(f"[*] {keyword}: {self.json['keywords'][keyword]}")
commands = "'add <keyword> <password>' to add an entry to the DB.\n'change <keyword> <password>' to change the password of an existing entry to <password>.\n'delete <keyword>' to delete an entry from the DB.\n'list' to list all entries in the DB.\n'fetch <keyword>' to copy the password of an existing entry to your clipboard.\n'show <keyword>' to display the password of an existing entry on the screen.\n'exit' to save the changes to the DB and exit the password manager.\n"
def encrypt(data, password):
    # Derive a symmetric key using the passsword and a fresh random salt.
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt,
        iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    # Encrypt the message.
    f = Fernet(base64.urlsafe_b64encode(key))
    encData = f.encrypt(data.encode("utf-8"))

    return encData, salt

def decrypt(encData, password, salt):
    # Derive the symmetric key using the password and provided salt.
    kdf = PBKDF2HMAC(
        algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt,
        iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    # Decrypt the message
    f = Fernet(base64.urlsafe_b64encode(key))
    data = f.decrypt(encData)

    return data.decode("utf-8")

def manager(argv):
    tprint("pypasman")
    try:
        opts, args = getopt.getopt(argv,"f:nh",["file=","new", "help"])
    except getopt.GetoptError:
        print('[!] No arguments were given. Run "python ./manager.py --help" for help.')
        sys.exit(64)
    if not opts:
        print('[!] No arguments were given. Run "python ./manager.py --help" for help.')
    for opt, arg in opts:
        if opt in ("-f", "--file"):
            print('[*] Trying to reach DB file '+arg)
            if os.path.isfile(arg):
                shell(arg)
            else:
                print('[!] No such file. Run "python ./manager.py --new" to create a new DB.')
                sys.exit(64)
        elif opt in ("-n", "--new"):
            print('[*] Creating a new DB.')
            init = create()
            if init:
                shell(init)
            else:
                print('[!] Failed to create a new DB file, shutting down.')
                sys.exit(64)
        elif opt in ("-h", "--help"):
            helpText()
        else:
            print(f'[!] Invalid argument given - {opt}. Run "python ./manager.py --help" for help.')
            sys.exit(64)
def helpText():
    print("Run 'python ./manage.py --new' to create a new .ppm database or 'python ./manage.py --file <filename>' to open an existing one.")
def create():
    name = input('[?] DB filename: ')
    if os.path.isfile(name+'.ppm'):
        print(f'[!] File {name}.ppm already exists in the current directory.')
        return False
    userPassword = input('[?] Create a password for the new DB: ')
    data = {"keywords":{}}
    try:
        save(data, userPassword, name+'.ppm')
        print(f"[*] Successfully created {name}.ppm")
    except Exception as e:
        print("[!] Failed to save due to the following exception: "+type(e).__name__)
        sys.exit(64)
    return name+'.ppm'
def save(data, password, name):
    data = json.dumps(data)
    encData, salt  = encrypt(data, password)
    encData = salt + "--START--".encode("utf-8") + encData 
    with open(name, "wb") as file:
        file.write(encData)
def openDB(name, password):
    try:
        file = open(name, 'rb').read().split(b'--START--')
        if len(file)!=2:
            raise Exception("The DB file is damaged.")
        salt, encData = file
        data = decrypt(encData, password, salt)
        data = json.loads(data[data.find("{"):data.rfind("}")+1].replace("'", "\""))
        return data
    except Exception as e:
        print("[!] Password is incorrect or the DB file is damaged. An exception has been raised: "+type(e).__name__)
        sys.exit(64)
    
def shell(name):
    password = input("[!] Enter the password to unlock the DB (repeat the same password if you're creating a new DB): ")
    data = Data(openDB(name, password))
    print("[*] Successfully opened the DB. List all the commands: 'help'")
    while True:
        command, *args = input(f"{name} >>> ").split(" ")
        if command == "help":
            print(commands)
        elif command == "exit":
            save(str(data.json), password, name)
            exit()
        else:
            execute = getattr(data, command, False)
            if execute:
                execute(*args)
                save(str(data.json), password, name)
            else:
                print(f"[!] The command {command} doesn't exist. Type 'help' to list all the available commands.")

if __name__=='__main__':
    manager(sys.argv[1:])
import sys
import os
import secrets
import random
from signal import signal, SIGINT
import argparse
import getpass
import hashlib
import base64
from Crypto.Cipher import AES
import json
import pickle
import codecs
from Crypto import Random
import pyperclip
import time

pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class PWManager():
    def create_password(self, length=16, alhpanumericonly=False):
        symbols = "abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ1234567890!@#$%&*()-_"
        if alhpanumericonly:
            symbols = "abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ1234567890"
        password = ''
        for i in range(length):
            password = password + random.choice(symbols)
        return password


    def encrypt(self, data, key):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphered = iv + cipher.encrypt(pad(data))
        return ciphered

    
    def decrypt(self, data, key):
        iv = data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cleartext_padded = cipher.decrypt(data[16:])
        cleartext = unpad(cleartext_padded)
        return cleartext


    def create_non_secret(self):
        return secrets.token_hex(32)
    

    def file_exists(self, filename):
        try:
            f = open(filename)
        except IOError:
            return False
        return True
    

    def password_is_valid(self, password, pwdb):
        non_secret = pwdb.get('non_secret')
        pw_confirm_enc = pwdb.get('check')
        key = hashlib.sha512(non_secret.join(password).encode()).hexdigest().encode("utf-8")[:32]
        pw_confirm_dec = self.decrypt(pw_confirm_enc, key).decode()
        if pw_confirm_dec == "passwordisvalid":
            return True
        else:
            return False


    def read_credential_names(self, pwdb_file="", pwdb_password=""):
        non_secret = ""
        if pwdb_file == "":
            pwdb_file = input("enter pwdb filename:")
        if pwdb_password == "":
            pwdb_password = getpass.getpass(f"enter password for pwdb ({pwdb_file}):")
        with open(pwdb_file, "rb") as infile:
            database = pickle.load(infile)
            non_secret = database['non_secret']
            nonsecretpw = non_secret + pwdb_password
            key = hashlib.sha512(nonsecretpw.encode()).hexdigest().encode("utf-8")[:32]
            credentials = database['pwdb']['credentials']
            for credential in credentials:
                name_enc = credential['name']
                name_dec = self.decrypt(name_enc, key)
                print(name_dec)


    def add_credentials(self, pwdb_file, pwdb_password="", cred_name="", cred_username="", cred_password=""):
        non_secret = ""
        database = {}
        if pwdb_password == "":
            pwdb_password = getpass.getpass(f"enter password for pwdb ({pwdb_file}):")
        with open(pwdb_file, "rb") as infile:
            database = pickle.load(infile)
            non_secret = database.get('non_secret')
        nonsecretpw = non_secret + pwdb_password
        key = hashlib.sha512(nonsecretpw.encode()).hexdigest().encode("utf-8")[:32]
        if not self.password_is_valid(pwdb_password, database):
            print("password was invalid")
            sys.exit(0)
        
        if cred_name == "":
            cred_name = input("name:")
        if cred_username == "":
            cred_username = input("username:")
        if cred_password == "":
            cred_password = getpass.getpass("password (press [ENTER] for random password):")
            if cred_password == "":
                cred_password = self.create_password(length=32)

        cred_name_enc = self.encrypt(cred_name, key)
        cred_username_enc = self.encrypt(cred_username, key)
        cred_password_enc = self.encrypt(cred_password, key)
        
        with open(pwdb_file, "wb") as outfile:
            credential = {"name": cred_name_enc, "username": cred_username_enc, "password": cred_password_enc}
            database['pwdb']['credentials'].append(credential)
            print(database)
            pickle.dump(database, outfile)


    def get_username_and_pw_for_credential(self, database, credential_name, password):
        non_secret = database.get('non_secret')
        nonsecretpw = non_secret + password
        key = hashlib.sha512(nonsecretpw.encode()).hexdigest().encode("utf-8")[:32]
        credentials = database.get('pwdb').get('credentials')

        for credential in credentials:
            name_dec = self.decrypt(credential.get('name'), key)
            if name_dec.decode() == credential_name:
                try:
                    username_dec = self.decrypt(credential.get('username'), key).decode()
                    pyperclip.copy(username_dec)
                    print("username copied to clipboard")
                    input("Press [ENTER] to continue to password")
                    pyperclip.copy("")
                    print("username was cleared from the clipboard")
                    password_dec = self.decrypt(credential.get('password'), key).decode()
                    pyperclip.copy(password_dec)
                    print("password copied to clipboard (auto-clear clipboard in 20 seconds)...")
                    time.sleep(20)
                except KeyboardInterrupt:
                    print("\nInterrupted (Ctrl-C).")
                    decide_clear = input("Clear clipboard?(y/n):")
                    if decide_clear[0] == "y":
                        pyperclip.copy("")
                        print("clipboard cleared")
                    else:
                        print("clipboard not cleared")
                finally:
                    pyperclip.copy("")
                    print("username/password was cleared from the clipboard")
                

    def get_username_for_credential(self, database, credential_name, password):
        non_secret = database.get('non_secret')
        nonsecretpw = non_secret + password
        key = hashlib.sha512(nonsecretpw.encode()).hexdigest().encode("utf-8")[:32]
        credentials = database.get('pwdb').get('credentials')
        for credential in credentials:
            name_dec = self.decrypt(credential.get('name'), key)
            if name_dec.decode() == credential_name:
                username_dec = self.decrypt(credential.get('username'), key).decode()
                pyperclip.copy(username_dec)
                print("Username copied to clipboard (clearing in 20 seconds). Press Ctrl-C to terminate (and clear clipboard)")
                time.sleep(20)
                pyperclip.copy("")

    
    def get_password_for_credential(self, database, credential_name, password):
        non_secret = database.get('non_secret')
        nonsecretpw = non_secret + password
        key = hashlib.sha512(nonsecretpw.encode()).hexdigest().encode("utf-8")[:32]
        credentials = database.get('pwdb').get('credentials')
        for credential in credentials:
            name_dec = self.decrypt(credential.get('name'), key)
            if name_dec.decode() == credential_name:
                password_dec = self.decrypt(credential.get('password'), key).decode()
                pyperclip.copy(password_dec)
                print("Password copied to clipboard (clearing in 20 seconds). Press Ctrl-C to terminate (and clear clipboard)")
                time.sleep(20)
                pyperclip.copy("")

    
    def list_credential_names(self, database, password):
        non_secret = database.get('non_secret')
        nonsecretpw = non_secret + password
        key = hashlib.sha512(nonsecretpw.encode()).hexdigest().encode("utf-8")[:32]
        credentials = database.get('pwdb').get('credentials')
        for i in range(0, len(credentials)):
            name_dec = self.decrypt(credentials[i].get('name'), key).decode()
            counter = i + 1
            print(f"{counter}:{name_dec}")

    
    def delete_credential(self, pwdb_file, credential_name, password):
        database = {}
        non_secret = database.get('non_secret')
        nonsecretpw = non_secret + password
        key = hashlib.sha512(nonsecretpw.encode()).hexdigest().encode("utf-8")[:32]
        with open(pwdb_file, "rb") as infile:
            database = pickle.load(infile)
            credentials = database.get('pwdb').get('credentials')
            for i in range(0, len(credentials) - 1):
                credname_dec = self.decrypt(credentials[i].get('name'), key).decode()
                print(credentials[i])
                if credname_dec == credential_name:
                    credentials.remove(credentials[i])
                    print(credentials[i])
            database['pwdb']['credentials'] = credentials
        
        with open(pwdb_file, "wb") as outfile:
            pickle.dump(database, outfile)
        print(f"Credentials with name {credential_name} was removed from pwdb ({pwdb_file})")


    def create_new_database(self):
        password = getpass.getpass("password for new database:")
        non_secret = self.create_non_secret()
        nonsecretpw = non_secret + password
        key = hashlib.sha512(nonsecretpw.encode()).hexdigest().encode("utf-8")[:32]

        pwdb = {
            "credentials": []
        }
        database = {
            "non_secret": non_secret,
            "check": self.encrypt("passwordisvalid", key),
            "pwdb": pwdb
        }
        filename = input("filename for database file:")
        print(filename[-5:])
        if filename[-5:] != ".pwdb":
            filename = filename + ".pwdb"

        with open(filename, "wb") as outfile:
            pickle.dump(database, outfile)
        
        print("Database created")
        decide_add_more_credentials = "y"
        decide_add_credential = input("add first credential?(y/n):")
        if decide_add_credential[0] == "y":
            cred_name = input("name (unique):")
            cred_username = input("username:")
            cred_password = getpass.getpass("password:")
            self.add_credentials(filename, pwdb_password=password, cred_name=cred_name, cred_username=cred_username, cred_password=cred_password)
            while decide_add_more_credentials == "y":
                decide_add_more_credentials = input("add more credentials?(y/n):")
                if decide_add_more_credentials != "y":
                    break
                cred_name = input("name (unique):")
                cred_username = input("username:")
                cred_password = getpass.getpass("password:")
                self.add_credentials(filename, pwdb_password=password, cred_name=cred_name, cred_username=cred_username, cred_password=cred_password)
        else:
            print("Password database created without any credentials")


def main(argv):
    pwmanager = PWManager()
    if len(argv) is 0:
        print(f'No arguments passed')
        decide_new = input("Would you like to initialize a new password database?(y/n):")
        if decide_new[0] == "y":
            print("yes")
            pwmanager.create_new_database()
        else:
            pwmanager.read_credential_names()
            print("no")
    options = get_opts(argv)

    if options.inputfile and options.listcreds and pwmanager.file_exists(options.inputfile):
        with open(options.inputfile, "rb") as infile:
            password = getpass.getpass("password:")
            database = pickle.load(infile)
            if pwmanager.password_is_valid(password, database):
                pwmanager.list_credential_names(database, password)
        sys.exit(0)


    if options.new:
        pwmanager.create_new_database()
        sys.exit(0)
    
    if options.inputfile and options.delcred and options.credname:
        password = getpass.getpass("password:")
        pwmanager.delete_credential(options.inputfile, options.credname, password)
        sys.exit(0)
    
    if options.inputfile and options.addnew and pwmanager.file_exists(options.inputfile):
        print(options.addnew)
        with open(options.inputfile, "rb") as infile:
            password = getpass.getpass("password:")
            database = pickle.load(infile)
            if pwmanager.password_is_valid(password, database):
                pwmanager.add_credentials(options.inputfile)
        sys.exit(0)

    
    if options.inputfile and options.credname:
        print(options.inputfile)
        print(options.credname)
        if pwmanager.file_exists(options.inputfile):
            with open(options.inputfile, "rb") as infile:
                password = getpass.getpass("password:")
                database = pickle.load(infile)
                #check if only want username or only want password
                if pwmanager.password_is_valid(password, database):
                    print(options.username)
                    print(options.password)
                    if options.username and options.password:
                        pwmanager.get_username_and_pw_for_credential(database, options.credname, password)
                    elif options.username and not options.password:
                        pwmanager.get_username_for_credential(database, options.credname, password)
                    elif options.password and not options.username:
                        print("check")
                        pwmanager.get_password_for_credential(database, options.credname, password)
                    else:
                        if pwmanager.password_is_valid(password, database):
                            pwmanager.get_username_and_pw_for_credential(database, options.getpass, password)
                else:
                    print("Authentication failure")
        sys.exit(0)


def get_opts(args):
    parser = argparse.ArgumentParser(description="Password database")
    parser.add_argument("-i", "--inputfile", dest="inputfile", help="File in which the password database resides.", type=str)
    parser.add_argument("-c", "--credname", dest="credname", help="Name of credential to get details for.", type=str)
    parser.add_argument("-l", "--list", dest="listcreds", help="List credential names (not username or password)", action="store_true")
    parser.add_argument("-a", "--addnew", dest="addnew", help="Add new credential set to the database.", action="store_true")
    parser.add_argument("-n", "--new", dest="new", help="Create new password database.", action="store_true")
    parser.add_argument("-u", "--username", dest="username", help="Get username.", action="store_true")
    parser.add_argument("-p", "--password", dest="password", help="Get password.", action="store_true")
    parser.add_argument("-r", "--delcred", dest="delcred", help="Remove credentials with given name", action="store_true")
    options = parser.parse_args(args)
    return options

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print("\nInterrupted (Ctrl-C).")
        decide_clear = input("Clear clipboard?(y/n):")
        if decide_clear[0] == "y":
            pyperclip.copy("")
            print("clipboard cleared")
        else:
            print("clipboard not cleared")

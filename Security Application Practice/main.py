
import sys
import os
import pandas as pd
import pickle
from types import NoneType
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from PyQt6.QtWidgets import QMainWindow, QWidget, QGridLayout, \
QLabel, QLineEdit, QPushButton, QApplication, QComboBox, QFileDialog, QInputDialog

#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#
#https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.AES#

#GUI Main Class
class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.gen_senders_keys()
        self.gen_receivers_keys()
        #Initialize Main Window
        self.setWindowTitle("Digital Envelope")
        self.setFixedSize(1000, 800)
        self.setStyleSheet(
            "font-family: garamond; \
             color: white; \
             font-size: 32px; \
             background-color: #663399;")        

        #Widgets       
        container = QWidget()
        self.setCentralWidget(container)
        self.line_input = QLineEdit()
        self.line_output = QLineEdit()
        label_input = QLabel(text="Input:")
        label_output = QLabel(text="Output:")
        options = ["Encrypt", "Decrypt"]
        self.combo_box = QComboBox()
        self.combo_box.addItems(options)
        
        # Added for encryption mode selection
        self.mode_combo_box = QComboBox()
        self.mode_combo_box.addItems(["CBC", "CTR"])
        
        # For user choice on file saving format
        self.file_format_combo_box = QComboBox()
        self.file_format_combo_box.addItems(["csv", "txt", "pickle"])
        
        # for save and load buttons
        save_button = QPushButton(text="Save")
        load_button = QPushButton(text="Load")


        button = QPushButton(text="Enter")

        #Format
        button.setStyleSheet("border-radius: 12px; background-color: black;")
        self.line_input.setStyleSheet("background-color: white; color: black")
        self.line_output.setStyleSheet("background-color: white; color: black")
        
        #Layout        
        layout = QGridLayout()              
        layout.addWidget(label_input, 0, 0)
        layout.addWidget(self.line_input, 1, 0)   
        layout.addWidget(label_output, 2, 0)         
        layout.addWidget(self.line_output, 3, 0)
        layout.addWidget(QLabel("Mode:"), 4, 0)            # label for mode selection
        layout.addWidget(self.mode_combo_box, 5, 0)        # added for mode selection
        layout.addWidget(QLabel("Action:"), 6, 0)          # label for the action selection
        layout.addWidget(self.combo_box, 7, 0)
        layout.addWidget(QLabel("File Format:"), 8, 0)     # label for file format 
        layout.addWidget(self.file_format_combo_box, 9, 0) # Combo box for file format
        layout.addWidget(save_button, 10, 0)
        layout.addWidget(load_button, 11, 0)

        layout.addWidget(button, 12, 0)        
        container.setLayout(layout)

        #Signals
        button.clicked.connect(self.button_clicked)
        save_button.clicked.connect(self.save_to_file)
        load_button.clicked.connect(self.load_button_clicked)
    
    #Events
    def button_clicked(self):       
        input_msg = self.line_input.text()
        
        action_index = self.combo_box.currentIndex()  # get action index
        mode_index = self.mode_combo_box.currentIndex()
        #file_format = self.file_format_combo_box.currentIndex() # get selected file format

        if action_index == 0:    # Encrypt
            output_msg, encrypted_key = self.encrypt_digital_env(input_msg, mode_index)
            self.ciphertext = output_msg        # stores ciphertext for file saving
            self.encrypted_key = encrypted_key  # stores encrypted key for file saving

        elif action_index == 1:  # Decrypt
            output_msg = self.decrypt_digital_env(input_msg, mode_index)


        self.line_output.setText(output_msg)


    # Save and load buttons clicked functions
    def save_to_file(self):
        
        if self.ciphertext is None: #or self.encrypted_key is None:
            print("No data to save.")
            return

        # Get the selected file format
        file_format = self.file_format_combo_box.currentText()  


        # Create the data to save
        data_to_save = {
            "ciphertext": self.ciphertext,
            "encrypted_key": self.encrypted_key.hex()
        }

        
        file_name, _ = QFileDialog.getSaveFileName(self, "Save File", "", f"Files (*{file_format})")
        
        if file_name:
            # Append the chosen file format if not included
            if not file_name.endswith(file_format):
                file_name += f".{file_format}"
            
            # Save data in the selected format
            if file_format == "csv":
                import pandas as pd
                df = pd.DataFrame([data_to_save])
                df.to_csv(file_name, index=False)
            elif file_format == "txt":
                with open(file_name, 'w') as f:
                    f.write(f"Ciphertext: {data_to_save['ciphertext']}\n")
                    f.write(f"Encrypted Key: {data_to_save['encrypted_key']}\n")
            elif file_format == "pickle":
                with open(file_name, 'wb') as f:
                    pickle.dump(data_to_save, f)
                 
    def load_button_clicked(self):

            file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "Files (*.csv *.txt *.pickle)")

            if not file_name:
                print("No file selected.")
                return

            file_format = self.file_format_combo_box.currentText()

            try:
                if file_format == "csv":
                    df = pd.read_csv(file_name)
                    ciphertext = df['ciphertext'].iloc[0]
                    encrypted_key = df['encrypted_key'].iloc[0]

                elif file_format == "txt":
                    with open(file_name, 'r') as f:
                        lines = f.readlines()
                        ciphertext = lines[0].split(": ")[1].strip()
                        encrypted_key = lines[1].split(": ")[1].strip()

                elif file_format == "pickle":
                    with open(file_name, 'rb') as f:
                        data_loaded = pickle.load(f)
                        ciphertext = data_loaded['ciphertext']
                        encrypted_key = data_loaded['encrypted_key']

                else:
                    raise ValueError("Unsupported file format")



                # Set the loaded value to the input box
                self.line_input.setText(ciphertext)
                # decided not to make another box for key, want it to be hidden

            except Exception as e:
                print(f"An error occured: {e}")



    def encrypt_digital_env(self, plaintext, mode_index):

        plaintext = plaintext.encode()

        key_iv, ciphertext = self.symmetric_encryption(plaintext, mode_index)
        encrypted_key = self.asymmetric_encrypt(key_iv)
        signature = self.sign(plaintext)
        
        digital_envelope = self.package_envelope(encrypted_key, ciphertext, signature)

        return digital_envelope.hex() , encrypted_key
    
    def decrypt_digital_env(self, digital_envelope, mode_index):

        digital_envelope = bytes.fromhex(digital_envelope)
        encrypted_key, ciphertext, signature = self.unpackage_envelope(digital_envelope)
        
        decrypted_key_iv = self.asymmetric_decrypt(encrypted_key)

        plaintext = self.symmetric_decryption(ciphertext, decrypted_key_iv, mode_index)

        if self.verify_signature(signature, plaintext):
            plaintext = plaintext.decode()
            return plaintext
        else:
            return "Invalid Signature"


    def gen_senders_keys(self):
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            )
       
    def gen_receivers_keys(self):
        
        self.public_key = self.private_key.public_key()

        
    def symmetric_encryption(self, plaintext, mode_index):

        key = os.urandom(32)
        iv = os.urandom(16)
        
        key_iv = key + b":" + iv # delimiter to separte key and iv

        if mode_index == 0:     # CBC
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()

            padder = PKCS7(algorithms.AES.block_size).padder()
            padded_plaintext = padder.update(plaintext) + padder.finalize()
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        elif mode_index == 1:   # CTR
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) 
            # no padding needed for CTR

        return (key_iv, ciphertext)
    
    def symmetric_decryption(self, ciphertext, decrypted_key_iv, mode_index):


        key, iv = decrypted_key_iv.split(b":")
       

        if mode_index == 0:    # CBC
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()


        elif mode_index == 1:  # CTR
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
        return plaintext
    

    def asymmetric_encrypt(self, key_iv):

        encrypted_key = self.public_key.encrypt(
            key_iv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_key
    
    def asymmetric_decrypt(self, encrypted_key):

        decrypted_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted_key


    def sign(self, plaintext):

        signature = self.private_key.sign(
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature
    
    def verify_signature(self, signature, plaintext):
        try:
            self.public_key.verify(
                signature,
                plaintext,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    

    def package_envelope(self, encrypted_key, ciphertext, signature):

        digital_envelope = encrypted_key + ciphertext + signature

        return digital_envelope
    
    def unpackage_envelope(self, digital_envelope):
        encrypted_key = digital_envelope[:256]
        ciphertext = digital_envelope[256:-256]
        signature = digital_envelope[-256:]

        return (encrypted_key, ciphertext, signature)
    


###############################################################################



def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

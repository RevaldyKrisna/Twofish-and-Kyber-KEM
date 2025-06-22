import sys
import os
import socket
import json
import time
import numpy as np
from tkinter import (Tk, Label, Button, Text, Scrollbar, Frame, 
                    StringVar, Entry, filedialog, messagebox)
from tkinter.ttk import Progressbar
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_256, SHAKE256
from Crypto.Util.Padding import pad
from twofish import Twofish

class KyberKEM:
    def __init__(self, k=2, n=256, q=3329, eta1=3, eta2=2):
        self.k = k
        self.n = n
        self.q = q
        self.eta1 = eta1
        self.eta2 = eta2
        self.d = 12

    def encapsulate(self, pk):
        t_list, seed_hex = pk
        t = np.array(t_list)
        seed = bytes.fromhex(seed_hex)
        
        A = self.generate_matrix_from_seed(seed)
        m = get_random_bytes(32)
        r = self.reconstruct_r_from_m(m)
        e1 = np.array([self.sample_poly_cbd(self.eta2) for _ in range(self.k)])
        e2 = self.sample_poly_cbd(self.eta2)
        u = np.array([(sum(self.poly_mul(A[j][i], r[j]) for j in range(self.k)) + e1[i]) % self.q 
                     for i in range(self.k)])
        m_poly = self.encode_message(m)
        v = (sum(self.poly_mul(t[i], r[i]) for i in range(self.k)) + e2 + m_poly) % self.q
        u_compressed = self.compress_polyvec(u)
        v_compressed = self.compress_poly(v)
        ss = self.generate_shared_secret(r, u_compressed, v_compressed)
        return (u_compressed, v_compressed), ss, m.hex()

    def generate_matrix_from_seed(self, seed):
        shake = SHAKE256.new(seed)
        A = np.zeros((self.k, self.k, self.n), dtype=int)
        for i in range(self.k):
            for j in range(self.k):
                buffer = shake.read(self.n * 3)
                for idx in range(self.n):
                    val = int.from_bytes(buffer[3*idx:3*(idx+1)], 'little')
                    A[i][j][idx] = val % self.q
        return A

    def sample_poly_cbd(self, eta):
        poly = np.zeros(self.n, dtype=int)
        for i in range(self.n):
            a = sum(get_random_bytes(eta))
            b = sum(get_random_bytes(eta))
            poly[i] = (a - b) % self.q
        return poly

    def poly_mul(self, a, b):
        result = np.zeros(self.n, dtype=int)
        for i in range(self.n):
            for j in range(self.n):
                k = (i + j) % self.n
                if i + j >= self.n:
                    result[k] = (result[k] - a[i]*b[j]) % self.q
                else:
                    result[k] = (result[k] + a[i]*b[j]) % self.q
        return result

    def compress_polyvec(self, polyvec):
        return [self.compress_poly(p) for p in polyvec]

    def compress_poly(self, poly):
        return [int(x) >> (self.d) for x in poly]

    def encode_message(self, message):
        hashed = SHA3_256.new(message).digest()
        poly = np.frombuffer(hashed, dtype=np.uint8)
        padded = np.zeros(self.n, dtype=int)
        padded[:len(poly)] = poly
        return padded % self.q

    def generate_shared_secret(self, r, u_compressed, v_compressed):
        data = b''.join(r[i].tobytes() for i in range(self.k)) + bytes(u_compressed[0]) + bytes(v_compressed)
        return SHA3_256.new(data).digest()

    def reconstruct_r_from_m(self, m):
        hashed = SHA3_256.new(m).digest()
        return np.array([
            np.frombuffer(SHAKE256.new(hashed + bytes([i])).read(self.n * 2), dtype=np.uint16) % self.q
            for i in range(self.k)
        ])

def encrypt_file(file_path, key):
    output_file_path = file_path + ".enc"
    t_cipher = Twofish(key[:16])
    chunk_size = 64 * 1024  # 64KB

    iv = get_random_bytes(16)
    with open(file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
        outfile.write(iv)

        file_data = infile.read()
        if len(file_data) == 0:
            # Handle edge case: file kosong tetap diberi padding
            padded = pad(b'', 16)
        else:
            padded = pad(file_data, 16)

        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            encrypted = t_cipher.encrypt(block)
            outfile.write(encrypted)

    return output_file_path


def validate_file(file_path):
    """Validate the file meets requirements"""
    allowed_extensions = ['.pdf', '.docx']
    file_ext = os.path.splitext(file_path)[1].lower()
    
    if file_ext not in allowed_extensions:
        raise ValueError("Only PDF and DOCX files are allowed.")
    
    file_size = os.path.getsize(file_path)
    if file_size == 0:
        raise ValueError("File is empty (0 bytes).")
    if file_size > 10 * 1024 * 1060:
        raise ValueError("File size exceeds 10MB limit.")
    
    return True

class SenderGUI:
    def __init__(self, master):
        self.master = master
        master.title("Kyber KEM File Sender")
        master.geometry("600x500")
        
        # File Selection
        self.file_label = Label(master, text="Select File to Send:")
        self.file_label.pack(anchor="w", padx=10, pady=5)
        
        self.file_frame = Frame(master)
        self.file_frame.pack(fill="x", padx=10, pady=5)
        
        self.file_path_var = StringVar()
        self.file_path_edit = Entry(self.file_frame, textvariable=self.file_path_var)
        self.file_path_edit.pack(side="left", fill="x", expand=True)
        
        self.browse_button = Button(self.file_frame, text="Browse", command=self.browse_file)
        self.browse_button.pack(side="left", padx=5)
        
        # Status Display
        self.status_var = StringVar()
        self.status_var.set("Status: Ready")
        self.status_label = Label(master, textvariable=self.status_var, anchor="w")
        self.status_label.pack(fill="x", padx=10, pady=5)
        
        # Log Display
        self.log_frame = Frame(master)
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_scroll = Scrollbar(self.log_frame)
        self.log_scroll.pack(side="right", fill="y")
        
        self.log_display = Text(self.log_frame, yscrollcommand=self.log_scroll.set)
        self.log_display.pack(fill="both", expand=True)
        
        self.log_scroll.config(command=self.log_display.yview)
        
        # Progress Bar
        self.progress_bar = Progressbar(master, orient="horizontal", length=580, mode="determinate")
        self.progress_bar.pack(padx=10, pady=5)
        
        # Send Button
        self.send_button = Button(master, text="Send File", command=self.send_file)
        self.send_button.pack(pady=10)
        
        # VM IP is hardcoded as per your requirement
        self.vm_ip = '192.168.1.10'
        
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select File", 
            filetypes=[("PDF or DOCX Files", "*.pdf *.docx")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.log_message(f"Selected file: {file_path}")
            
    def log_message(self, message):
        self.log_display.insert("end", message + "\n")
        self.log_display.see("end")
        self.master.update()
        
    def send_file(self):
        file_path = self.file_path_var.get()
        if not file_path:
            self.log_message("Error: No file selected")
            return
            
        try:
            validate_file(file_path)
            self.progress_bar["value"] = 10
            
            # Connect to VM (receiver)
            self.log_message(f"Connecting to VM at {self.vm_ip}...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.vm_ip, 65432))
                self.progress_bar["value"] = 20
                
                # Receive public key from receiver
                data = s.recv(4096)
                message = json.loads(data.decode())
                if message['type'] != 'pk':
                    raise ValueError("Expected public key from receiver")
                
                pk = message['data']
                self.progress_bar["value"] = 30
                
                # Initialize Kyber and encapsulate
                kyber = KyberKEM()
                start_time = time.time()
                ciphertext, ss, m_hex = kyber.encapsulate(pk)
                encapsulate_time = time.time() - start_time
                self.progress_bar["value"] = 40
                
                # Encrypt the file
                start_time = time.time()
                encrypted_path = encrypt_file(file_path, ss)
                encrypt_time = time.time() - start_time
                self.progress_bar["value"] = 60
                
                # Read encrypted file data
                with open(encrypted_path, 'rb') as f:
                    file_data = f.read()
                self.progress_bar["value"] = 70
                
                # Prepare and send message
                filename = os.path.basename(file_path)
                message = {
                    'type': 'encrypted_file',
                    'ciphertext': ciphertext,
                    'm': m_hex,
                    'filename': filename,
                    'file_data': file_data.hex()
                }
                
                s.sendall(json.dumps(message).encode() + b'\n')
                self.progress_bar["value"] = 90
                
                # Display metrics
                self.log_message("\n=== Performance Metrics ===")
                self.log_message(f"Encapsulation Time: {encapsulate_time:.4f} seconds")
                self.log_message(f"File Encryption Time: {encrypt_time:.4f} seconds")
                self.log_message(f"Total Processing Time: {encapsulate_time + encrypt_time:.4f} seconds")
                self.log_message(f"File sent successfully: {filename}")
                self.log_message(f"Encrypted file kept at: {encrypted_path}")
                
                self.progress_bar["value"] = 100
                self.status_var.set("Status: File sent successfully")
                
        except Exception as e:
            self.log_message(f"Error sending file: {str(e)}")
            self.status_var.set("Status: Error occurred")
            self.progress_bar["value"] = 0
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = Tk()
    app = SenderGUI(root)
    root.mainloop()
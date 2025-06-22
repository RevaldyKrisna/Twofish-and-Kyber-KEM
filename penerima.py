from queue import Queue
import sys
import os
import socket
import json
import time
import threading
import numpy as np
from tkinter import (Tk, Label, Button, Text, Scrollbar, Frame, 
                    StringVar, Toplevel, messagebox)
from tkinter.ttk import Progressbar
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_256, SHAKE256
from Crypto.Util.Padding import unpad
from twofish import Twofish

class KyberKEM:
    def __init__(self, k=2, n=256, q=3329, eta1=3, eta2=2):
        self.k = k
        self.n = n
        self.q = q
        self.eta1 = eta1
        self.eta2 = eta2
        self.d = 12

    def generate_keypair(self):
        seed = get_random_bytes(32)
        A = self.generate_matrix_from_seed(seed)
        s = np.array([self.sample_poly_cbd(self.eta1) for _ in range(self.k)])
        e = np.array([self.sample_poly_cbd(self.eta1) for _ in range(self.k)])
        t = np.array([(sum(self.poly_mul(A[i][j], s[j]) for j in range(self.k)) + e[i]) % self.q 
                     for i in range(self.k)])
        return (t.tolist(), seed.hex()), s.tolist()

    def decapsulate(self, sk_list, ciphertext, m_hex):
        s = np.array(sk_list)
        u_compressed, v_compressed = ciphertext
        m = bytes.fromhex(m_hex)
        
        u = self.decompress_polyvec(u_compressed)
        v = self.decompress_poly(v_compressed)
        r = self.reconstruct_r_from_m(m)
        ss = self.generate_shared_secret(r, u_compressed, v_compressed)
        return ss

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

    def decompress_polyvec(self, polyvec_compressed):
        return np.array([self.decompress_poly(p) for p in polyvec_compressed])

    def compress_poly(self, poly):
        return [int(x) >> (self.d) for x in poly]

    def decompress_poly(self, poly_compressed):
        return np.array([x << self.d for x in poly_compressed])

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

def decrypt_file(file_path, key):
    original_ext = os.path.splitext(file_path[:-4])[1]
    output_file_path = file_path.replace('.enc', original_ext)

    t_cipher = Twofish(key[:16])

    with open(file_path, 'rb') as infile:
        iv = infile.read(16)
        encrypted_data = infile.read()

    # Gunakan bytearray untuk efisiensi
    decrypted_data = bytearray()
    for i in range(0, len(encrypted_data), 16):
        block = encrypted_data[i:i+16]
        if len(block) < 16:
            continue
        decrypted_data.extend(t_cipher.decrypt(block))

    try:
        decrypted_data = unpad(decrypted_data, 16)
    except ValueError as e:
        print(f"Unpadding error: {e}")
        return None

    with open(output_file_path, 'wb') as outfile:
        outfile.write(decrypted_data)

    return output_file_path



class FileTransfer:
    def __init__(self, host='0.0.0.0', port=65432, gui=None):
        self.host = host
        self.port = port
        self.kyber = KyberKEM()
        self.file_queue = Queue()
        self.received_files = []
        self.socket = None
        self.running = False
        self.keygen_time = 0
        self.decrypt_time = 0
        self.gui = gui  # Reference to GUI for logging

    def log_message(self, message):
        """Thread-safe logging to both GUI and console"""
        print(message)  # Always log to console
        if self.gui:
            # Use after() to schedule GUI update in main thread
            self.gui.master.after(0, lambda: self.gui.log_message(message))

    def start_receiver(self):
        """Start the receiver server that listens for incoming connections"""
        self.running = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        self.log_message(f"Receiver started on {self.host}:{self.port}")

        # Generate keypair for this session with time measurement
        start_time = time.time()
        self.pk, self.sk = self.kyber.generate_keypair()
        self.keygen_time = time.time() - start_time
        self.log_message(f"Public key generated in {self.keygen_time:.4f} seconds")
        self.log_message("Public key ready for sharing")

        threading.Thread(target=self._accept_connections, daemon=True).start()

    def _accept_connections(self):
        while self.running:
            try:
                conn, addr = self.socket.accept()
                self.log_message(f"Connection from {addr}")
                threading.Thread(target=self._handle_connection, args=(conn,), daemon=True).start()
            except OSError:
                if self.running:
                    self.log_message("Socket accept error")
                break

    def _handle_connection(self, conn):
        try:
            # First send our public key to the sender
            conn.sendall(json.dumps({'type': 'pk', 'data': self.pk}).encode() + b'\n')

            # Receive the file data
            data = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk

            if not data:
                return

            # Parse the received data
            try:
                messages = data.split(b'\n')
                for msg in messages:
                    if not msg:
                        continue
                    message = json.loads(msg.decode())
                    
                    if message['type'] == 'encrypted_file':
                        ciphertext = message['ciphertext']
                        m_hex = message['m']
                        filename = message['filename']
                        file_data = bytes.fromhex(message['file_data'])
                        
                        # Save encrypted file temporarily
                        temp_path = f"temp_{filename}.enc"
                        with open(temp_path, 'wb') as f:
                            f.write(file_data)
                        
                        # Decapsulate to get shared secret with time measurement
                        start_time = time.time()
                        ss = self.kyber.decapsulate(self.sk, ciphertext, m_hex)
                        decapsulate_time = time.time() - start_time
                        
                        # Decrypt the file with time measurement
                        start_time = time.time()
                        decrypted_path = decrypt_file(temp_path, ss)
                        decrypt_time = time.time() - start_time
                        
                        # Clean up
                        os.remove(temp_path)
                        
                        self.received_files.append(decrypted_path)
                        self.log_message("\n=== Performance Metrics ===")
                        self.log_message(f"Key Generation Time: {self.keygen_time:.4f} seconds")
                        self.log_message(f"Decapsulation Time: {decapsulate_time:.4f} seconds")
                        self.log_message(f"File Decryption Time: {decrypt_time:.4f} seconds")
                        self.log_message(f"Total Processing Time: {self.keygen_time + decapsulate_time + decrypt_time:.4f} seconds")
                        self.log_message(f"File received and decrypted: {decrypted_path}")
                        
            except json.JSONDecodeError as e:
                self.log_message(f"Invalid data received: {e}")
            except Exception as e:
                self.log_message(f"Error processing file: {e}")
                
        except Exception as e:
            self.log_message(f"Error handling connection: {e}")
        finally:
            conn.close()

class ReceiverGUI:
    def __init__(self, master):
        self.master = master
        master.title("Kyber KEM File Receiver")
        master.geometry("600x500")
        
        # Status Display
        self.status_var = StringVar()
        self.status_var.set("Status: Ready to receive files")
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
        
        # Button Frame
        self.button_frame = Frame(master)
        self.button_frame.pack(pady=10)
        
        self.start_button = Button(self.button_frame, text="Start Receiver", command=self.start_receiver)
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = Button(self.button_frame, text="Stop Receiver", command=self.stop_receiver, state="disabled")
        self.stop_button.pack(side="left", padx=5)
        
        # Initialize file transfer with reference to this GUI
        self.file_transfer = FileTransfer(gui=self)
        self.receiver_thread = None
        
    def log_message(self, message):
        """Add message to log display (called from main thread)"""
        self.log_display.insert("end", message + "\n")
        self.log_display.see("end")
        self.master.update_idletasks()
        
    def start_receiver(self):
        self.log_message("Starting receiver...")
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_var.set("Status: Running - waiting for connections")
        
        # Create a thread for the receiver
        self.receiver_thread = threading.Thread(
            target=self.run_receiver, 
            daemon=True
        )
        self.receiver_thread.start()
        
    def stop_receiver(self):
        self.log_message("Stopping receiver...")
        self.file_transfer.running = False
        if self.file_transfer.socket:
            try:
                self.file_transfer.socket.close()
            except:
                pass
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_var.set("Status: Stopped")
        
    def run_receiver(self):
        self.file_transfer.start_receiver()
        
        # Update GUI with received files
        while self.file_transfer.running:
            time.sleep(0.1)
            if self.file_transfer.received_files:
                for file in self.file_transfer.received_files:
                    self.log_message(f"Received file: {file}")
                self.file_transfer.received_files = []
                
    def on_closing(self):
        self.stop_receiver()
        self.master.destroy()

if __name__ == "__main__":
    root = Tk()
    app = ReceiverGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
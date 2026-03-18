import random

# Inisialisasi S-BOX (Substitusi)
SBOX = [(i * 137 + 19) % 256 for i in range(256)]

def xor(a, b): 
    return bytes([a[i] ^ b[i] for i in range(len(a))])

# === 2 FUNGSI DASAR: SUBSTITUSI & PERMUTASI ===
def round_f(R, K):
    # 1. Fungsi Substitusi (Menggunakan S-BOX)
    t = [SBOX[R[i] ^ K[i]] for i in range(4)]
    # 2. Fungsi Permutasi (Shift-Left)
    return bytes([t[1], t[2], t[3], t[0]])

# === ALGORITMA FEISTEL ===
def feistel_enc(b, keys):
    L, R = b[:4], b[4:]
    for i in range(4): # 4 Putaran Enkripsi
        f = round_f(R, keys[i])
        L, R = R, xor(L, f)
    return R + L

def feistel_dec(b, keys):
    L, R = b[:4], b[4:]
    for i in range(3, -1, -1): # Kunci dibalik untuk dekripsi
        f = round_f(R, keys[i])
        L, R = R, xor(L, f)
    return R + L

# === PADDING ===
def pad(d):
    p = 8 - (len(d) % 8)
    return d + bytes([p] * p)

def unpad(d): 
    return d[:-d[-1]]

# === MODE OPERASI 1: CBC (Cipher Block Chaining) ===
def cbc_enc(pt, keys, iv):
    pt = pad(pt)
    prev = iv
    out = b''
    for i in range(0, len(pt), 8):
        b = xor(pt[i:i+8], prev)
        c = feistel_enc(b, keys)
        out += c
        prev = c
    return out

def cbc_dec(ct, keys, iv):
    prev = iv
    out = b''
    for i in range(0, len(ct), 8):
        c = ct[i:i+8]
        d = feistel_dec(c, keys)
        out += xor(d, prev)
        prev = c
    return unpad(out)

# === MANAJEMEN KUNCI MANUAL ===
def generate_subkeys(key_str):
    # Jika input kurang dari 8 karakter, tambah 'X'
    key_str = (key_str + "XXXXXXXX")[:8]
    kb = key_str.encode('utf-8')
    return [kb[0:4], kb[4:8], kb[0:4], kb[4:8]]

# === ENCODER & DECODER KARAKTER MANUAL (PENGGANTI LIBRARY BASE64) ===
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def custom_encode(byte_data):
    # Ubah byte jadi biner, lalu potong per 6-bit agar jadi huruf/angka biasa
    bin_str = "".join([f"{b:08b}" for b in byte_data])
    pad_len = (6 - (len(bin_str) % 6)) % 6
    bin_str += "0" * pad_len
    res = "".join([B64_ALPHABET[int(bin_str[i:i+6], 2)] for i in range(0, len(bin_str), 6)])
    return res + "=" * (pad_len // 2)

def custom_decode(text_str):
    # Kembalikan huruf/angka tadi menjadi raw byte
    text_str = text_str.rstrip("=")
    bin_str = "".join([f"{B64_ALPHABET.index(c):06b}" for c in text_str])
    excess = len(bin_str) % 8
    if excess != 0:
        bin_str = bin_str[:-excess]
    return bytes([int(bin_str[i:i+8], 2) for i in range(0, len(bin_str), 8)])


# === PROGRAM UTAMA (SISTEM MENU) ===
def main():
    while True:
        print("\n" + "="*45)
        print(" SISTEM KRIPTOGRAFI BLOCK CIPHER CBC ")
        print("="*45)
        print("1. Enkripsi Pesan")
        print("2. Dekripsi Pesan")
        print("3. Keluar")
        pilihan = input("Pilih menu (1/2/3): ")

        if pilihan == '1':
            msg = input("\n[-] Masukkan Plaintext   : ").encode('utf-8')
            key_in = input("[-] Masukkan Kunci Rahasia (maks 8 huruf): ")
            keys = generate_subkeys(key_in)
            
            iv = bytes([random.randint(0, 255) for _ in range(8)])
            
            ct = cbc_enc(msg, keys, iv)
            
            # --- FITUR BARU: MENCETAK BINER SEBELUM JADI KARAKTER ---
            combined_data = iv + ct
            # Format setiap byte menjadi biner 8-bit (contoh: 01000001) lalu gabung dengan spasi
            biner_str = " ".join([f"{b:08b}" for b in combined_data])
            
            # Gunakan fungsi manual kita untuk mengubah byte gabungan jadi karakter
            hasil_char = custom_encode(combined_data)
            
            print("\n[+] STATUS: BERHASIL DIENKRIPSI!")
            print("[+] Ciphertext (Biner)   :\n    " + biner_str)
            print("\n[+] Ciphertext (Karakter):\n    " + hasil_char)
            print("\n    (Copy teks KARAKTER di atas untuk dicoba pada menu Dekripsi)")

        elif pilihan == '2':
            char_in = input("\n[-] Masukkan Ciphertext (Karakter): ")
            key_in = input("[-] Masukkan Kunci Rahasia        : ")
            keys = generate_subkeys(key_in)
            
            try:
                # Gunakan fungsi manual kita (tanpa library)
                data = custom_decode(char_in)
                
                iv = data[:8]
                ct = data[8:]
                
                pt = cbc_dec(ct, keys, iv)
                print("\n[+] STATUS: BERHASIL DIDEKRIPSI!")
                print("[+] Plaintext Asli:", pt.decode('utf-8'))
            except Exception as e:
                print("\n[!] GAGAL DEKRIPSI! Pastikan Ciphertext dan Kunci yang dimasukkan benar.")

        elif pilihan == '3':
            print("Keluar dari program...")
            break
        else:
            print("Pilihan tidak valid, coba lagi.")

if __name__ == "__main__":
    main()

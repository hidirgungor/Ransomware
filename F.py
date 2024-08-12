import os
import hashlib
import base64
import random
import platform
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def t9Xl4_sNv8():

    name_values = [66, 108, 97, 110, 103]
    transformed_values = []
    for i, val in enumerate(name_values):

        step1 = (val + (i + 1) * 5) % 256
        step2 = step1 ^ (i * 11)
        transformed_values.append(step2)

    hidden_name = ''.join(chr(v) for v in transformed_values)
    shuffled_name = ''.join(random.sample(hidden_name, len(hidden_name)))
    return shuffled_name

def s7Hc2_zKj1():

    cpu_info = platform.processor()
    disk_info = str(os.statvfs('/').f_bsize) + str(os.statvfs('/').f_blocks)
    mac_info = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 2)][::-1])
    signature = t9Xl4_sNv8()
    combined_info = cpu_info + disk_info + mac_info + signature
    shuffled_info = ''.join(random.sample(combined_info, len(combined_info)))
    return hashlib.sha256(shuffled_info.encode()).hexdigest()

def f9Jx1_wQb7(jD3k, t8Rb=b'xjF0_vTz4'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=t8Rb,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(jD3k.encode())

def c4Nk2_yUl9(vQd5, q8Ml):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(q8Ml), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(vQd5.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message).decode()

def r6Xy3_oLk8(m5Gq, q8Ml):
    m5Gq = base64.b64decode(m5Gq)
    iv = m5Gq[:16]
    cipher = Cipher(algorithms.AES(q8Ml), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(m5Gq[16:]) + decryptor.finalize()
    return decrypted_message.decode()

def d9Cr5_aPq6(d4t4):
    obfuscated = ''.join(chr((ord(char) + 3) % 256) for char in d4t4)
    return ''.join(random.sample(obfuscated, len(obfuscated)))

def p1Lk3_vFs7(d4t4):
    deobfuscated = ''.join(chr((ord(char) - 3) % 256) for char in d4t4)
    return ''.join(sorted(deobfuscated, key=lambda x: ord(x)))

def q3Zx4_hJk0(f2Dk, q8Ml):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(q8Ml), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()  
    with open(f2Dk, 'rb') as f:
        f1l3_d4t4 = f.read()  

    f1l3_d4t4 += t9Xl4_sNv8().encode()

    encrypted_data = encryptor.update(f1l3_d4t4) + encryptor.finalize()
    obfuscated_encrypted = d9Cr5_aPq6(base64.b64encode(iv + encrypted_data).decode())
  
    with open(f2Dk + '.enc', 'w') as f_enc:
        f_enc.write(obfuscated_encrypted)
    
    print(f"R2mH9 '{f2Dk}' X8pQ3d 0bfZ6d K4mL2g.")

def z7Xr8_yKl1(f6Hn, q8Ml):
    with open(f6Hn, 'r') as f_enc:
        obfuscated_encrypted = f_enc.read()
    
    encrypted_data = base64.b64decode(p1Lk3_vFs7(obfuscated_encrypted).encode())
    
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(q8Ml), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()  

    if decrypted_data.endswith(t9Xl4_sNv8().encode()):
        decrypted_data = decrypted_data[:-len(t9Xl4_sNv8())]
    
    original_file_path = f6Hn.replace('.enc', '')
    with open(original_file_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"R2mH9 '{original_file_path}' Q6kR4d S2fN8k.")

def n2Kl6_rFt4():
    jD3k = s7Hc2_zKj1()
    q8Ml = f9Jx1_wQb7(jD3k)

    s5Rt3_kLp9 = "Z8lM2r_X1jD4k"
    c9Mj7_oLp4 = c4Nk2_yUl9(s5Rt3_kLp9, q8Ml)
    obfuscated_encrypted = d9Cr5_aPq6(c9Mj7_oLp4)

    print("Q2mY6d X1rG9s K4pL8:", obfuscated_encrypted)

    try:
        p2Lk7_vFs3 = p1Lk3_vFs7(obfuscated_encrypted)
        decrypted_message = r6Xy3_oLk8(p2Lk7_vFs3, q8Ml)
        print("S1gN4j K2mP6x:", decrypted_message)
    except Exception as e:
        print(f"S2gH8f D6jR2z: {e}")

def z1Qw9_uYt2():
    n2Kl6_rFt4()
 
    f2Dk = 'K2pS9d_F8gL1h.txt'  
    jD3k = s7Hc2_zKj1()
    q8Ml = f9Jx1_wQb7(jD3k)
    
    q3Zx4_hJk0(f2Dk, q8Ml)
    z7Xr8_yKl1(f2Dk + '.enc', q8Ml) 

if __name__ == "__main__":
    z1Qw9_uYt2()

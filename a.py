import socket
import math
import sys
from os import urandom
from Crypto import Cipher
from Crypto.Cipher import AES

# Adresa si portul KM-ului
km_host = "127.0.0.1"
km_port = 8000

# Adresa si portul nodului B
b_host = "127.0.0.1"
b_port = 8001

# Alegem modul de AES
aes_mode = AES.MODE_ECB
if len(sys.argv) > 1 and sys.argv[1] == "CFB":
	aes_mode = AES.MODE_CFB
print("AES Mode:", aes_mode)

# Citim key prime din fisier
file = open("key_prime", "rb")
key_prime = file.read()
file.close()

# Socketul pentru conexiunea la KM
# AF_INET Familia de adrese folosita, IPV4
# SOCK_STREAM Tipul de socket folosit, TCP
km_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Ne conectam la KM pentru a primi cheia criptata si iv-ul folosit la criptare
km_sock.connect((km_host, km_port))
print("Conectat la KM")
key_encrpyted = km_sock.recv(16)
print("Key encrypted:", key_encrpyted)

# Decriptam cheia
aes = AES.new(key_prime, AES.MODE_ECB)
key = aes.decrypt(key_encrpyted)
print("Key:", key)

# Cream socketul pentru nodul B
b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Ne conectam la nodul B si ii trimitem modul de criptare si cheia criptata
b_sock.connect((b_host, b_port))
print("Conectat la B")
b_sock.sendall(aes_mode.to_bytes(4, byteorder="big"))
b_sock.sendall(key_encrpyted)

# Asteptam mesajul de incepere a comunicarii
msg = str(b_sock.recv(5), "ascii")
if msg == "Start":
	print("Am primit confirmarea")
else:
	print("Confirmare esuata")
	sys.exit(1)

# Citim fisierul
file = open("lorem.txt", "rb")
content = file.read()
file.close()

# Calculam numarul de chunk-uri
chunk_number = math.ceil(len(content)/16)
print("Numarul de chunkuri:", chunk_number)

# Ne pregatim pentru encriptare
# Instantam aes iarasi cu cheia decriptata pentru a o folosi la criptarea chunkurilor folosite la ECB si CFB
aes = AES.new(key, AES.MODE_ECB)
# Comunicam lui B numarul de chunk-uri
b_sock.sendall(chunk_number.to_bytes(4, byteorder='big'))

# ECB
if aes_mode == AES.MODE_ECB:
	# Criptam si trimitem chunk cu chunk
	for c in range(0, chunk_number):
		chunk = content[c*16:c*16+16]	

		# Daca chunk-ul are o lungime mai mica de 16bytes, 128bits, apenduim
		if len(chunk)<16:
			for i in range(0, 16-len(chunk)):
				chunk += bytes(' ', "ascii")

		encrypted_chunk = aes.encrypt(chunk)
		b_sock.sendall(encrypted_chunk)
else:
	# Generam si trimitem IV-ul
	iv = urandom(16)
	print("IV:", iv)
	b_sock.sendall(iv)
	iv_encrypted = aes.encrypt(iv)
	anterior = None

	first_chunk = content[0: 16]
	# Xorare array de bytes
	first_ciphertext = bytes(a^b for (a,b) in zip(first_chunk, iv_encrypted))

	# Trimitem primul chunk the ciphertext
	b_sock.sendall(first_ciphertext)

	# Ne pregatim pentru un loop
	anterior = first_ciphertext
	for c in range(1, chunk_number):
		chunk = content[c*16:c*16+16]

		if len(chunk)<16:
			for i in range(0, 16-len(chunk)):
				chunk += bytes(' ', "ascii")

		anterior_encrypted = aes.encrypt(anterior)
		ciphertext = bytes(a^b for (a,b) in zip(anterior_encrypted, chunk))
		b_sock.sendall(ciphertext)
		anterior = ciphertext

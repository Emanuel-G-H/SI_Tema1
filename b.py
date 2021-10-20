import socket
from sys import byteorder
from Crypto.Cipher import AES

# Adresa la care asculta
HOST = "127.0.0.1"
# Portul la care asculta
PORT = 8001

# Citim din fisier key_prime
file = open("key_prime", "rb")
key_prime = file.read()
file.close()

# AF_INET Familia de adrese folosita, IPV4
# SOCK_STREAM Tipul de socket folosit, TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Facem bind la socket pe adresa si portul de mai sus
sock.bind((HOST, PORT))
# Ascultam pentru conexiuni
sock.listen(1)

while True:
	conn, addr = sock.accept()
	print("Conexiune noua de la :", addr[0])

	# Primim modul de AES
	aes_mode = int.from_bytes(conn.recv(4), byteorder="big", signed=True)
	print("AES Mode:", aes_mode)

	# Primim cheia criptata si o decriptam
	key_encrypted = conn.recv(16)
	print("Key encrypted:", key_encrypted)
	aes = AES.new(key_prime, AES.MODE_ECB)
	key = aes.decrypt(key_encrypted)
	print("Key:", key)

	# Trimitem mesajul de incepere a comunicarii
	print("Confirmam lui A")
	conn.sendall(bytes("Start", "ascii"))

	# Ne pregatim pentru decriptare
	# Instantam aes iarasi cu cheia decriptata pentru a o folosi la decriptarea ECB sau CFB
	aes = AES.new(key, AES.MODE_ECB)

	# Primim numarul de chunk-uri
	chunk_number = int.from_bytes(conn.recv(4), byteorder="big", signed=True)
	print("Numarul de chunkuri:", chunk_number)

	content = bytes()
	#ECB
	if aes_mode == AES.MODE_ECB:
		# Primim si decriptam chunk cu chunk pe care il apenduim apoi la content
		for c in range(0, chunk_number):
			chunk = conn.recv(16)
			decrypted_chunk = aes.decrypt(chunk)
			content += decrypted_chunk
	#CFB
	else:
		# Primim IV-ul
		iv = conn.recv(16)
		print("IV:", iv)
		iv_encrypted = aes.encrypt(iv)
		anterior = None

		# Primim primul chunk the ciphertext
		first_ciphertext = conn.recv(16)
		first_chunk = bytes(a^b for(a,b) in zip(first_ciphertext, iv_encrypted))
		content = first_chunk

		# Ne pregatim pentru un loop
		anterior = first_ciphertext
		for c in range(1, chunk_number):
			ciphertext = conn.recv(16)
			anterior_encrypted = aes.encrypt(anterior)
			chunk = bytes(a^b for (a,b) in zip(ciphertext, anterior_encrypted))
			anterior = ciphertext
			content += chunk

	# Scriem content-ul in fisier in functie de modul de criptare
	file = None
	if(aes_mode == AES.MODE_ECB):
		file = open("output_ecb.txt", "wb")
	else:
		file = open("output_cfb.txt", "wb")
	file.write(content)
	file.close()

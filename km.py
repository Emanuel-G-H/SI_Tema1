import socket
from os import urandom
from Crypto.Cipher import AES

# Adresa la care asculta
HOST = "127.0.0.1"
# Portul la care asculta
PORT = 8000

# AF_INET Familia de adrese folosita, IPV4
# SOCK_STREAM Tipul de socket folosit, TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Facem bind la socket pe adresa si portul de mai sus
sock.bind((HOST, PORT))
# Ascultam pentru conexiuni
sock.listen(1)

# Citim din fisier key_prime
key_prime = None
file = open("key_prime", "rb")
key_prime = file.read()
file.close()

# Acceptam conexiuni
while True:
	conn, addr = sock.accept()
	print("Conexiune noua de la:", addr[0])
	
	# Generam o cheie noua aleator, 16 bytes = 128 bits
	key = urandom(16)
	print("Key:", key)
	
	# Criptam cheia
	aes = AES.new(key_prime, AES.MODE_ECB)
	key_encrypted = aes.encrypt(key)
	print("Key encrypted:", key_encrypted)
	
	# Trimitem IV-ul
	conn.sendall(key_encrypted)
	conn.close()




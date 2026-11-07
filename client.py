
import socket

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

CLIENT_IP = "127.0.0.1"
CLIENT_PORT = 5001

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind((CLIENT_IP, CLIENT_PORT))

client.settimeout(5)

while True:
    message = input("Enter message (or exit): ")

    if message.lower() == "exit":
        break

    client.sendto(message.encode("utf-8"), (SERVER_IP, SERVER_PORT))

    try:
        data, address = client.recvfrom(4096)
        print("Server:", data.decode("utf-8"))

    except socket.timeout:
        print("Server did not respond.")

client.close()

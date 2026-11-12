import socket
import itertools

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

CLIENT_IP = "127.0.0.1"
CLIENT_PORT = 5001

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind((CLIENT_IP, CLIENT_PORT))

client.settimeout(5)

rq_numbers = itertools.count(1)

while True:
    message = input("Enter message (or exit): ")

    if message.lower() == "exit":
        break

    command, _, rest = message.partition(" ")
    message = f"{command.upper()} {next(rq_numbers)} {rest}".strip()
    client.sendto(message.encode("utf-8"), (SERVER_IP, SERVER_PORT))

    try:
        data, address = client.recvfrom(4096)
        reply = data.decode("utf-8")
        print("Server:", reply)


        if reply.startswith("REGISTERED "):
            count = int(reply.split()[-1])
            rq_numbers = itertools.count(count + 1)

    except socket.timeout:
        print("Server did not respond.")

client.close()
import socket
import itertools
import os
import queue
import random
import sys
import threading

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

CLIENT_IP = "127.0.0.1"
# Usage: python client.py [UDP_port] [Name]
# Running several clients at once needs a different port for each one.
CLIENT_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7001

# Name used in ALERT_ACK. It is taken from the REGISTER command, or from the
# command line when the client was already registered in an earlier run.
client_name = sys.argv[2] if len(sys.argv) > 2 else None

# Packet-loss simulation for testing section 2.5: the fraction (0 to 1) of
# ALERT_ACK messages this client "loses" instead of sending.
ACK_LOSS = float(os.environ.get("CENRS_ACK_LOSS", "0"))

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind((CLIENT_IP, CLIENT_PORT))

# On Windows, don't let an unreachable server break recvfrom().
if hasattr(socket, "SIO_UDP_CONNRESET"):
    client.ioctl(socket.SIO_UDP_CONNRESET, False)

client.settimeout(0.5)

rq_numbers = itertools.count(1)

# Messages the server sends on its own; everything else is a reply to a request.
NOTIFICATIONS = ("ALERT", "ALL_CLEAR")

replies = queue.Queue()

# (Incident_ID, Version) pairs already processed, for duplicate detection.
seen_notifications = set()

running = True


def send_alert_ack(request_number, incident_id, version):
    if client_name is None:
        print("[!] Cannot send ALERT_ACK: name unknown (REGISTER first, "
              "or start with: python client.py <port> <name>)")
        return

    ack = f"ALERT_ACK {request_number} {incident_id} {version} {client_name}"

    if random.random() < ACK_LOSS:
        print("[sim] Dropped:", ack)
        return

    client.sendto(ack.encode("utf-8"), (SERVER_IP, SERVER_PORT))
    print("Sent:", ack)


def handle_notification(message):
    parts = message.split()
    kind = parts[0]

    if kind == "ALERT" and len(parts) >= 10:
        # ALERT RQ# Incident_ID Version Category Location Severity Title Description Attachment
        request_number, incident_id, version = parts[1], parts[2], parts[3]
        needs_ack = parts[6] == "CRITICAL"
    elif kind == "ALL_CLEAR" and len(parts) >= 5:
        # ALL_CLEAR RQ# Incident_ID Version Message (always acknowledged)
        request_number, incident_id, version = parts[1], parts[2], parts[3]
        needs_ack = True
    else:
        print("[!] Ignoring malformed notification:", message)
        return

    key = (incident_id, version)
    duplicate = key in seen_notifications

    # The ACK is sent again for a duplicate, because the server is
    # retransmitting only because our previous ACK was lost.
    if needs_ack:
        send_alert_ack(request_number, incident_id, version)

    if duplicate:
        print(f"Duplicate {kind} for {incident_id} version {version} ignored")
        return

    seen_notifications.add(key)

    if kind == "ALERT":
        print("\n*** " + parts[6] + " ALERT " + incident_id + " (version " + version + ") ***")
        print("    " + parts[4] + " at " + parts[5] + ": " + parts[7].replace("_", " "))
        print("    " + parts[8].replace("_", " "))
        if parts[9] != "NONE":
            print("    Attachment: " + parts[9])
    else:
        print("\n*** ALL CLEAR " + incident_id + " (version " + version + ") ***")
        print("    " + " ".join(parts[4:]).replace("_", " "))


def receive_loop():
    # Runs in the background so alerts are received (and acknowledged) even
    # while the user is typing a command.
    while running:
        try:
            data, address = client.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break

        message = data.decode("utf-8")

        if message.split(" ", 1)[0] in NOTIFICATIONS:
            print("\nServer:", message)
            handle_notification(message)
        else:
            replies.put(message)


receiver = threading.Thread(target=receive_loop, daemon=True)
receiver.start()

while True:
    message = input("Enter message (or exit): ")

    if message.lower() == "exit":
        break

    command, _, rest = message.partition(" ")
    message = f"{command.upper()} {next(rq_numbers)} {rest}".strip()

    # Throw away late replies to earlier requests.
    while not replies.empty():
        print("Late reply:", replies.get_nowait())

    client.sendto(message.encode("utf-8"), (SERVER_IP, SERVER_PORT))

    try:
        reply = replies.get(timeout=5)
        print("Server:", reply)

        if reply.startswith("REGISTERED "):
            count = int(reply.split()[-1])
            rq_numbers = itertools.count(count + 1)

            registered_name = rest.split()[0] if rest.split() else None
            if registered_name:
                client_name = registered_name

    except queue.Empty:
        print("Server did not respond.")

running = False
client.close()

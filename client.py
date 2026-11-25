import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import itertools
import json
import os
import queue
import random
import socket
import threading
from attachments import AttachmentServer, download_attachment, valid_file_name # For Feature 2.9: TCP listener, download function, filename check

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
SERVER_TCP_PORT = 6000
CLIENT_IP = "127.0.0.1"
CLIENT_PORT = 7007

# Feature 2.5: packet-loss simulation for testing. The fraction (0 to 1) of
# ALERT_ACK messages this client "loses" instead of sending.
ACK_LOSS = float(os.environ.get("CENRS_ACK_LOSS", "0"))

# Messages the server sends on its own; every other message is a reply to a request
NOTIFICATIONS = ("ALERT", "ALERT_UPDATE", "ALL_CLEAR")

replies = queue.Queue() # Replies to our requests, filled by the receiver thread
session = {"name": None} # Name used in ALERT_ACK (set on REGISTERED or with --name)
seen_notifications = set() # (Incident_ID, Version) pairs already processed, for duplicate detection

# Welcome menu: commands listed in the order of the project sections (type HELP to show it again)
def print_menu(udp_port, name):
    print(f"""
-------------------------------------------------------------------------------
WELCOME TO CENRS

Please choose a command from the menu below. Type HELP to show this menu again.
1. REGISTER Name Role IP UDP_Port TCP_Port
2. DE-REGISTER Name                 
3. SUBSCRIBE Location Category     
4. UNSUBSCRIBE Location Category    
5. PUBLISH_ALERT Category Location Severity Title Description Attachment
6. UPDATE_ALERT Incident_ID Severity Title Description
7. CLOSE_ALERT Incident_ID Reason   
8. STATUS_REPORT Incident_ID Name Status (SAFE / NEED_HELP / LEFT_AREA)
9. ATTACH_REQ Incident_ID File_Name 
10. GET_ACTIVE_ALERTS [Name]  
11. HELP      
11. EXIT

Locations:  HALL EV JMSB LOYOLA SGW ALL
Categories: FIRE SECURITY WEATHER POWER BUILDING GENERAL ALL
-------------------------------------------------------------------------------
""")

def request(client, command, number, arguments):
    # Throw away late replies to earlier requests
    while not replies.empty():
        print("Late reply:", replies.get_nowait())

    message = " ".join([command, str(number), *arguments])
    client.sendto(message.encode("utf-8"), (SERVER_IP, SERVER_PORT))
    try:
        reply = replies.get(timeout=5) # 5 seconds timeout for the server to respond
    except queue.Empty:
        print("Server did not respond.")
        return []
    print("Server:", reply)
    return reply.split()


# Feature 2.5: Reliable delivery of CRITICAL alerts / Feature 2.7: ALL_CLEAR
def send_alert_ack(client, request_number, incident_id, version):
    name = session["name"]
    if name is None:
        print("Cannot send ALERT_ACK: name unknown (REGISTER first, or start with --name)")
        return

    ack = f"ALERT_ACK {request_number} {incident_id} {version} {name}"
    if random.random() < ACK_LOSS:
        print("[sim] Dropped:", ack)
        return
    client.sendto(ack.encode("utf-8"), (SERVER_IP, SERVER_PORT))
    print("Sent:", ack)


def handle_notification(client, message):
    fields = message.split()
    kind = fields[0]

    if kind == "ALERT" and len(fields) >= 10:
        # ALERT RQ# Incident_ID Version Category Location Severity Title Description Attachment
        needs_ack = fields[6] == "CRITICAL"
    elif kind == "ALERT_UPDATE" and len(fields) >= 7:
        # Feature 2.6: ALERT_UPDATE RQ# Incident_ID Version Severity Title Description
        # A CRITICAL update is acknowledged like a CRITICAL alert
        needs_ack = fields[4] == "CRITICAL"
    elif kind == "ALL_CLEAR" and len(fields) >= 5:
        # ALL_CLEAR RQ# Incident_ID Version Message (always acknowledged)
        needs_ack = True
    else:
        print("Ignoring malformed notification:", message)
        return

    request_number, incident_id, version = fields[1], fields[2], fields[3]
    key = (incident_id, version)
    duplicate = key in seen_notifications

    # A duplicate is ACKed again: the server only retransmits because our ACK was lost
    if needs_ack:
        send_alert_ack(client, request_number, incident_id, version)

    if duplicate:
        print(f"Duplicate {kind} for {incident_id} version {version} ignored")
        return
    seen_notifications.add(key)

    if kind == "ALERT":
        print(f"\n*** {fields[6]} ALERT {incident_id} (version {version}) ***")
        print(f"    {fields[4]} at {fields[5]}: {fields[7].replace('_', ' ')}")
        print(f"    {fields[8].replace('_', ' ')}")
        if fields[9] != "NONE":
            print(f"    Attachment: {fields[9]} (download with: ATTACH_REQ {incident_id} {fields[9]})")
    elif kind == "ALERT_UPDATE":
        print(f"\n*** {fields[4]} UPDATE {incident_id} (version {version}) ***")
        print(f"    {fields[5].replace('_', ' ')}")
        print(f"    {fields[6].replace('_', ' ')}")
    else:
        print(f"\n*** ALL CLEAR {incident_id} (version {version}) ***")
        print("    " + " ".join(fields[4:]).replace("_", " "))


def receive_loop(client, stop):
    # Runs in the background so alerts are received and acknowledged even while
    # the user is typing or the main thread is waiting for a reply
    while not stop.is_set():
        try:
            data, address = client.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if address != (SERVER_IP, SERVER_PORT):
            continue
        message = data.decode("utf-8")
        if message.split(" ", 1)[0] in NOTIFICATIONS:
            print("\nServer:", message)
            handle_notification(client, message)
        else:
            replies.put(message)

# For 2.10: get the current active incidents from the server over TCP
def get_active_alerts(number, name):
    try:
        with socket.create_connection((SERVER_IP, SERVER_TCP_PORT), timeout=5) as connection:
            request_line = f"GET_ACTIVE_ALERTS {number} {name}"
            connection.sendall((request_line + "\n").encode("utf-8"))
            print("TCP sent:", request_line)

            with connection.makefile("r", encoding="utf-8") as incoming:
                header = incoming.readline().split()
                print("TCP received:", " ".join(header))

                # ACTIVE_ALERTS RQ# Number_Alerts
                if len(header) != 3 or header[0] != "ACTIVE_ALERTS" or not header[2].isdigit():
                    return

                # Read exactly Number_Alerts record lines
                for _ in range(int(header[2])):
                    record = incoming.readline().split()
                    if len(record) != 9:
                        print("Malformed record:", " ".join(record))
                        continue
                    incident_id, version, category, location, severity, status, title, description, attachment = record
                    print(f"  {incident_id} v{version} {severity} {category} at {location} [{status}]: "
                          f"{title.replace('_', ' ')} - {description.replace('_', ' ')} (attachment: {attachment})")
                    # Remember it, so a late UDP copy of the same version is not shown again
                    seen_notifications.add((incident_id, version))
    except OSError as error:
        print("GET_ACTIVE_ALERTS failed:", error)


# Section 4: a PUBLISHER/BOTH client keeps its role, TCP endpoint and the
# Incident_ID -> attachment file list in client_<Name>.json. When it is started
# again with --name, it restarts its TCP listener and serves the same files,
# so subscribers can still download attachments of incidents that are active.
def client_state_file(name):
    return f"client_{name}.json"


def save_client_state(name, role, publisher):
    if publisher is None or not valid_file_name(client_state_file(name)):
        return
    with publisher.attachments_lock:
        attachments = dict(publisher.attachments)
    state = {
        "role": role,
        "ip": publisher.server_address[0],
        "tcp_port": publisher.server_address[1],
        "attachments": attachments
    }
    try:
        # Temporary file + rename, so a crash never leaves a half-written file
        with open(client_state_file(name) + ".tmp", "w") as file:
            json.dump(state, file, indent=4)
        os.replace(client_state_file(name) + ".tmp", client_state_file(name))
    except OSError as error:
        print("Could not save", client_state_file(name) + ":", error)


def load_client_state(name):
    if not valid_file_name(client_state_file(name)):
        return None
    try:
        with open(client_state_file(name)) as file:
            state = json.load(file)
        return state if isinstance(state, dict) else None
    except (OSError, ValueError):
        return None  # no saved state (never was a publisher here) or unreadable file


def delete_client_state(name):
    try:
        os.remove(client_state_file(name))
    except OSError:
        pass


# Set up the client and reads commands
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--udp-port", type=int, default=CLIENT_PORT)
    # Feature 2.5: name for ALERT_ACK when this client was already registered in an earlier run
    parser.add_argument("--name")
    args = parser.parse_args()
    session["name"] = args.name
    stop_receiver = threading.Event()

    publisher = None # Holds the active TCP listener for a PUBLISHER/BOTH client
    registered_name = None
    registered_role = None
    rq_numbers = itertools.count(1) # next(rq_numbers) returns 1, 2, 3, ... for each new request

    try:
        # Open the UDP socket and create the download worker pool
        # AF_INET selects IPv4, SOCK_DGRAM creates a UDP socket
        # Up to 4 downloads at once; more than 4 downloads will be queued until a worker is available
        # The workers handle file transfers while the main thread can accept another command
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, ThreadPoolExecutor(max_workers=4) as downloads:
            # Bind the socket to this client’s local address (IP and UDP port)
            # Each local client has a different UDP port to let the server distinguish between them and send replies to the correct socket
            client.bind((CLIENT_IP, args.udp_port))
            # On Windows, don't let an unreachable server break recvfrom()
            if hasattr(socket, "SIO_UDP_CONNRESET"):
                client.ioctl(socket.SIO_UDP_CONNRESET, False)
            client.settimeout(0.5) # Lets the receiver thread check regularly whether it should stop
            threading.Thread(target=receive_loop, args=(client, stop_receiver), daemon=True).start()
            print_menu(args.udp_port, session["name"])

            # Section 4: a client restarted with --name is still registered on the
            # (persistent) server, so it resumes by syncing the active incidents it
            # may have missed while it was down. If the server is down, the user
            # can run GET_ACTIVE_ALERTS again later.
            if session["name"] is not None:
                # A publisher also restarts its attachment listener with the saved files
                state = load_client_state(session["name"])
                if state is not None and state.get("role") in ("PUBLISHER", "BOTH"):
                    try:
                        publisher = AttachmentServer((state["ip"], int(state["tcp_port"])))
                    except (OSError, KeyError, TypeError, ValueError) as error:
                        print("Cannot restart attachment listener:", error)
                    else:
                        publisher.attachments.update(state.get("attachments", {}))
                        publisher.start()
                        registered_name, registered_role = session["name"], state["role"]
                        print("Restored", len(publisher.attachments), "attachment(s) for", session["name"])

                print("Resuming as", session["name"] + ": syncing active alerts with the server...")
                get_active_alerts(next(rq_numbers), session["name"])

            while True:
                fields = input("Please enter a command from the menu (or HELP to show menu again): ").split()
                if not fields:
                    continue
                command, *arguments = fields # Separate the command from its arguments (1st word in 'command', the rest in 'arguments')
                command = command.upper()
                if command == "EXIT":
                    break

                if command == "HELP":
                    print_menu(args.udp_port, session["name"])
                    continue

                # For 2.10: GET_ACTIVE_ALERTS goes over TCP, not UDP
                if command == "GET_ACTIVE_ALERTS":
                    name = arguments[0] if arguments else session["name"]
                    if name is None:
                        print("Usage: GET_ACTIVE_ALERTS Name")
                        continue

                    # A client may only sync its own alerts
                    if session["name"] is not None and name != session["name"]:
                        print("You can only request your own alerts (you are " + session["name"] + ")")
                        continue

                    get_active_alerts(next(rq_numbers), name)
                    continue

                # Prepare a TCP listener for the PUBLISHER/BOTH client if registering with a valid TCP port
                listener = None # Holds the TCP listener that's being prepared; is closed if denied registration or exits before registration is completed
                if command == "REGISTER" and len(arguments) == 5:
                    name, role, ip, udp_port, tcp_port = arguments
                    
                    # Validate that the same registered name is not being used to change role or TCP endpoint without de-registering first
                    if (name == registered_name and role != registered_role) or (
                        publisher is not None and name == registered_name
                        and (ip, tcp_port) != (publisher.server_address[0], str(publisher.server_address[1]))
                    ):
                        print("De-register before changing your role or TCP endpoint.")
                        continue

                    # Validate that the role is either PUBLISHER/BOTH and the TCP port is valid
                    if role in ("PUBLISHER", "BOTH") and publisher is None:
                        try:
                            port = int(tcp_port)
                            if ip != CLIENT_IP or int(udp_port) != args.udp_port or not 1 <= port <= 65535:
                                raise ValueError("Use the client's local IP and UDP port and a valid TCP port.")
                            listener = AttachmentServer((ip, port))
                        except (OSError, ValueError) as error:
                            print("Cannot start attachment listener:", error)
                            continue

                # For a PUBLISH_ALERT command with an attachment, validate that the attachment filename is valid
                if command == "PUBLISH_ALERT" and len(arguments) == 6:
                    attachment = arguments[-1] # The final field is the attachment name
                    if attachment != "NONE" and not valid_file_name(attachment):
                        print("Use a filename from the publisher's working directory or NONE.")
                        continue

                number = next(rq_numbers) # Assign a number to the outgoing UDP command
                # An early TCP request waits for the server-assigned incident ID
                # The lock is used to prevent a race condition where the TCP handler might try to access the attachments dictionary while it's being modified by the main thread
                lock = publisher.attachments_lock if publisher and command == "PUBLISH_ALERT" else nullcontext()
                try:
                    # For a publisher’s PUBLISH_ALERT, 'with lock' holds the same lock the TCP handler uses when looking up attachments;
                    # for other commands, nullcontext() lets the block run without acquiring a lock
                    with lock:
                        # Send the UDP command to the server and wait for a reply
                        # Example: If the reply is 'ALERT_ACCEPTED 2 INC001', reply[2] is 'INC001';
                        # for a publication with 'map.pdf', the dictionary entry becomes 'publisher.attachments["INC001"] = "map.pdf"'
                        reply = request(client, command, number, arguments)
                        if (
                            publisher and command == "PUBLISH_ALERT" and len(arguments) == 6
                            and len(reply) == 3 and reply[:2] == ["ALERT_ACCEPTED", str(number)]
                            and arguments[-1] != "NONE"
                        ):
                            publisher.attachments[reply[2]] = arguments[-1]

                    # Section 4: remember the new incident's attachment on disk (after releasing the lock)
                    if publisher and command == "PUBLISH_ALERT" and len(reply) == 3 and reply[0] == "ALERT_ACCEPTED":
                        save_client_state(session["name"], registered_role, publisher)

                    # Handle the server's reply to the command and manage the TCP listener for a PUBLISHER/BOTH client:
                    # On 'REGISTERED', the client saves the accepted name and role
                    if command == "REGISTER" and len(arguments) == 5 and reply[:2] == ["REGISTERED", str(number)]:
                        registered_name, registered_role = arguments[:2]
                        session["name"] = registered_name # Used in ALERT_ACK
                        rq_numbers = itertools.count(int(reply[-1]) + 1) # The message count at the end of the reg reply is used to set the next request number
                        if listener is not None:
                            listener.start() # Start TCP listener in a background thread
                            publisher, listener = listener, None # Move the TCP listener into 'publisher' once it's running
                        if publisher is not None:
                            # Section 4: re-registering after a restart brings back the files published earlier
                            state = load_client_state(registered_name)
                            if state is not None:
                                with publisher.attachments_lock:
                                    for incident_id, file_name in state.get("attachments", {}).items():
                                        publisher.attachments.setdefault(incident_id, file_name)
                            save_client_state(registered_name, registered_role, publisher)
                    # On 'DEREGISTERED', the client clears the local reg and stops accepting new attachment connections
                    elif command == "DE-REGISTER" and reply[:2] == ["DEREGISTERED", str(number)]:
                        if registered_name is not None:
                            delete_client_state(registered_name) # Not registered any more, nothing to resume
                        registered_name = registered_role = None
                        session["name"] = None
                        if publisher is not None:
                            publisher.stop()
                            publisher = None
                    # For a subscriber's ATTACH_REQ, the server's ATTACH_INFO reply contains the publisher's TCP endpoint and the attachment filename;
                    # the client starts a download in a background thread
                    # session["name"] is also set by --name, so a restarted subscriber can still download
                    elif command == "ATTACH_REQ" and len(arguments) == 2 and session["name"]:
                        if len(reply) == 7 and reply[:3] == ["ATTACH_INFO", str(number), arguments[0]] and reply[-1] == arguments[1]:
                            endpoint = (reply[4], int(reply[5]))
                            downloads.submit(download_attachment, endpoint, next(rq_numbers), session["name"], *arguments)
                # Cleanup; close a prepared listener that never becomes the running publisher
                finally:
                    if listener is not None:
                        listener.server_close()
    # Allow end-of-input or Ctrl+C to end the session
    except (EOFError, KeyboardInterrupt):
        pass
    # Cleanup; stop the receiver thread and the running publisher's TCP listener if it exists
    finally:
        stop_receiver.set()
        if publisher is not None:
            publisher.stop()

if __name__ == "__main__":
    main()

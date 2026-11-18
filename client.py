import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import itertools
import socket
from time import monotonic # To measure the reply deadline independently of changes to the system clock
from attachments import AttachmentServer, download_attachment, valid_file_name # For Feature 2.9: TCP listener, download function, filename check

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
CLIENT_IP = "127.0.0.1"
CLIENT_PORT = 7001

def request(client, command, number, arguments):
    message = " ".join([command, str(number), *arguments])
    client.sendto(message.encode("utf-8"), (SERVER_IP, SERVER_PORT))
    deadline = monotonic() + 5 # 5 seconds timeout for the server to respond
    while monotonic() < deadline:
        client.settimeout(max(deadline - monotonic(), 0.001))
        try:
            data, address = client.recvfrom(4096)
        except socket.timeout:
            break
        if address != (SERVER_IP, SERVER_PORT):
            continue
        reply = data.decode("utf-8")
        print("Server:", reply)
        fields = reply.split()
        if fields and fields[0] != "ALERT":
            return fields
    print("Server did not respond.")
    return []

# Set up the client and reads commands
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--udp-port", type=int, default=CLIENT_PORT)
    args = parser.parse_args()

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
            while True:
                fields = input("Enter message (or exit): ").split()
                if not fields:
                    continue
                command, *arguments = fields # Separate the command from its arguments (1st word in 'command', the rest in 'arguments')
                command = command.upper()
                if command == "EXIT":
                    break

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

                    # Handle the server's reply to the command and manage the TCP listener for a PUBLISHER/BOTH client:
                    # On 'REGISTERED', the client saves the accepted name and role
                    if command == "REGISTER" and len(arguments) == 5 and reply[:2] == ["REGISTERED", str(number)]:
                        registered_name, registered_role = arguments[:2]
                        rq_numbers = itertools.count(int(reply[-1]) + 1) # The message count at the end of the reg reply is used to set the next request number
                        if listener is not None:
                            listener.start() # Start TCP listener in a background thread
                            publisher, listener = listener, None # Move the TCP listener into 'publisher' once it's running
                    # On 'DEREGISTERED', the client clears the local reg and stops accepting new attachment connections
                    elif command == "DE-REGISTER" and reply[:2] == ["DEREGISTERED", str(number)]:
                        registered_name = registered_role = None 
                        if publisher is not None:
                            publisher.stop()
                            publisher = None
                    # For a subscriber's ATTACH_REQ, the server's ATTACH_INFO reply contains the publisher's TCP endpoint and the attachment filename;
                    # the client starts a download in a background thread
                    elif command == "ATTACH_REQ" and len(arguments) == 2 and registered_name:
                        if len(reply) == 7 and reply[:3] == ["ATTACH_INFO", str(number), arguments[0]] and reply[-1] == arguments[1]:
                            endpoint = (reply[4], int(reply[5]))
                            downloads.submit(download_attachment, endpoint, next(rq_numbers), registered_name, *arguments)
                # Cleanup; close a prepared listener that never becomes the running publisher
                finally:
                    if listener is not None:
                        listener.server_close()
    # Allow end-of-input or Ctrl+C to end the session
    except (EOFError, KeyboardInterrupt):
        pass
    # Cleanup; stop the running publisher's TCP listener if it exists
    finally:
        if publisher is not None:
            publisher.stop()

if __name__ == "__main__":
    main()

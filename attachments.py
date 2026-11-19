import hashlib # For SHA-256; publisher computes a checksum for the file, subscriber computes its own checksum from the received bytes
import ntpath # To check Windows filename rules
from pathlib import PureWindowsPath, Path # To check Windows filename rules, to build/resolve filesystem paths
import os # To read metadata from an open file
import socket # For TCP connections to download attachments
from socketserver import ThreadingTCPServer, StreamRequestHandler # For handling multiple TCP connections, each handler with readable and writable streams
import stat # To check if a file is a regular file
from tempfile import NamedTemporaryFile # To create a temporary file for a download before renaming it to the final destination
from threading import Thread, Lock # To run the publisher’s listener in the background, to protect attachments dictionary from concurrent access

TIMEOUT = 5 # 5-second timeout for each socket
HEADER_LIMIT = 4096 # Maximum number of bytes allowed for the header
CHUNK_SIZE = 64 * 1024 # 64 KB = Size of each chunk to read from the file

# getattr() selects ntpath.isreserved() when available and supplies the PureWindowsPath check as a fallback
is_reserved = getattr(ntpath, "isreserved", lambda name: PureWindowsPath(name).is_reserved())

# Assume Windows OS; validate the filename according to Windows rules
def valid_file_name(name):
    return (
        bool(name)
        and name not in (".", "..", "NONE") # Reject single and double periods, and NONE
        and not any(char.isspace() or char in '/\\:<>|?*"\0' for char in name) # Reject whitespaces, path separators, special characters
        and not name.endswith(".") # Reject trialing periods
        and not is_reserved(name) # Reject reserved names like CON, PRN, AUX, NUL, COM1, LPT1, ...
    )

# Read a header line from the stream, decode it, and split it into fields
def read_header(stream):
    line = stream.readline(HEADER_LIMIT + 1) # Read header up to 1 byte beyond the limit to detect oversized headers
    
    # A valid header must end with a newline and be within the size limit
    if not line.endswith(b"\n") or len(line) > HEADER_LIMIT:
        raise ValueError("Invalid_Header")
    
    return line.decode("utf-8").split() # Decode the header from UTF-8 (bytes) to a string and split it into fields by whitespace

# Write a header line to the stream
def write_header(stream, message):
    stream.write((message + "\n").encode("utf-8")) # Encode the message to UTF-8 (string to bytes) and append a newline
    stream.flush() # Ensure the header is sent immediately without buffering
    print("TCP sent:", message) # Print the sent message

# Generate chunks of a file from a stream
def file_chunks(stream, size):
    while size:
        chunk = stream.read(min(CHUNK_SIZE, size)) # Read a chunk of the file, up to CHUNK_SIZE or the remaining size
       
        # The chunk must not be empty (incomplete transfer)
        if not chunk:
            raise ValueError("Incomplete_Transfer")
        
        size -= len(chunk) # Decrease the remaining size by the length of the chunk read
        yield chunk # Yield each chunk to the caller to allow processing the file in parts w/o loading the entire file into memory

# Handler for attachment requests
class AttachmentHandler(StreamRequestHandler):
    timeout = TIMEOUT # Set a timeout for the TCP connection to avoid hanging indefinitely

    def handle(self):
        try:
            fields = read_header(self.rfile) # Read the header from the incoming TCP stream and split it into fields
            print("TCP received:", " ".join(fields)) # Print the received fields
            
            # Log the request (command, request number, subscriber name, incident name, attachment filename)
            if len(fields) != 5 or fields[0] != "GET_ATTACHMENT": 
                return
            _, rq, subscriber, incident, name = fields
            
            # Validate the request number and filename
            if not rq.isdecimal() or not valid_file_name(name):
                write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} Invalid_Request")
                return

            # Let the handler take the lock while reading the shared dictionary
            # Match the incident ID to the publisher's attachment filename; if it doesn't match, return an error
            with self.server.attachments_lock:
                published_name = self.server.attachments.get(incident)
            if published_name != name:
                write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} Unknown_Attachment")
                return

            # Build the path in the publisher’s working directory and resolve it
            # Rejects a path that resolves outside that directory
            path = (self.server.directory / name).resolve()
            if path.parent != self.server.directory or not path.is_file():
                write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} File_Unavailable")
                return
            # Open the file in binary read mode to prepare for sending it over the TCP connection
            try:
                file = path.open("rb")
            # Handle errors when opening the file, such as permission issues or file not found
            except OSError:
                write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} File_Unavailable")
                return

            # Compute the SHA-256 checksum of the file and send it in chunks to the subscriber
            with file:
                # Get file metadata (file type and size)
                info = os.fstat(file.fileno())
                if not stat.S_ISREG(info.st_mode):
                    write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} File_Unavailable")
                    return
                
                size = info.st_size # Get the size of the file in bytes to send it in the header and to know how many bytes to read and send in chunks
                
                checksum = hashlib.sha256() # Create a SHA-256 hash object to compute the checksum of the file
                
                # Read the file in chunks and update the checksum
                try:
                    for chunk in file_chunks(file, size):
                        checksum.update(chunk)
                except (OSError, ValueError):
                    write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} File_Unavailable")
                    return

                file.seek(0) # Reset the file pointer to the beginning of the file to send it again in chunks after computing the checksum

                # Send the header with the request number, incident ID, attachment filename, file size, and checksum in hexadecimal format
                write_header(self.wfile, f"ATTACH_DATA {rq} {incident} {name} {size} {checksum.hexdigest()}")
                
                # Send each chunk of the file to the subscriber over the TCP connection
                # Reading twice lets the publisher announce the checksum before sending the file while keeping only chunks in memory
                for chunk in file_chunks(file, size):
                    self.wfile.write(chunk)

            # The publisher reads and logs the subscriber’s final response (ATTACH_OK or ATTACH_ERROR
            result = read_header(self.rfile)
            print(f"TCP received from {subscriber}:", " ".join(result))
        except (OSError, ValueError) as error:
            print("TCP attachment service:", error)

# TCP server listens for attachment requests from subscribers and serves the requested files
# Handles each connection in a separate thread
class AttachmentServer(ThreadingTCPServer):
    daemon_threads = True # Let the process exit even if a connection handler is still running

    # Constructor initialises the server
    def __init__(self, address):
        self.directory = Path.cwd().resolve() # Publisher's working directory; attachments must be in this directory
        self.attachments = {} # Dictionary that maps incident IDs to attachment filenames; used to validate requests and locate files
        self.attachments_lock = Lock() # Lock to protect the attachments dictionary from concurrent access by multiple threads
        super().__init__(address, AttachmentHandler) # Initialise the TCP server with the given address and the AttachmentHandler class to handle incoming requests

    # Start the server in a background thread to listen for incoming connections
    def start(self):
        Thread(target=self.serve_forever, daemon=True).start()
        print(f"Listening for attachments on TCP port {self.server_address[1]}")

    # Stop the server and close the socket to stop accepting new connections
    def stop(self):
        self.shutdown()
        self.server_close()

# Download an attachment from a publisher's TCP endpoint and save it to the downloads directory
def download_attachment(endpoint, rq, subscriber, incident, name):
    # The filename and incident ID must be valid because both will become part of the output path
    if not valid_file_name(name) or not valid_file_name(incident):
        print("Attachment download failed: Invalid_File_Name")
        return

    identity = [str(rq), incident, name] # The identity of the attachment request
    temporary_path = None # Initially 'None' because the subscriber hasn't created a temporary file yet
    try:
        # Create a TCP connection to the publisher's endpoint with a timeout to avoid hanging indefinitely
        with socket.create_connection(endpoint, timeout=TIMEOUT) as connection:
            
            # Use the connection's file-like objects for reading and writing to simplify sending and receiving data
            with connection.makefile("rb") as incoming, connection.makefile("wb") as outgoing:
                
                write_header(outgoing, f"GET_ATTACHMENT {rq} {subscriber} {incident} {name}")
                header = read_header(incoming)
                print("TCP received:", " ".join(header))

                # The publisher's response must either be ATTACH_ERROR with the correct identity or ATTACH_DATA with the correct identity; otherwise, the subscriber ignores it
                if len(header) == 5 and header[0] == "ATTACH_ERROR" and header[1:4] == identity:
                    return
                try:
                    # Validate that the publisher's ATTACH_DATA response matches the expected format
                    if len(header) != 6 or header[:4] != ["ATTACH_DATA", *identity]:
                        raise ValueError("Unexpected_Response")
                    size_text, expected_checksum = header[4:]
                    # Validate that the file size is a decimal number and convert it to an integer
                    if not size_text.isdecimal():
                        raise ValueError("Invalid_File_Size")
                    size = int(size_text)

                    # Create a temporary file in the downloads directory to store the incoming attachment before renaming it to the final destination
                    checksum = hashlib.sha256() # Create a SHA-256 hash object to compute the checksum of the received file
                    directory = Path("downloads")
                    directory.mkdir(exist_ok=True)
                    with NamedTemporaryFile(dir=directory, delete=False) as file:
                        temporary_path = Path(file.name)
                        for chunk in file_chunks(incoming, size):
                            file.write(chunk)
                            checksum.update(chunk)
                    if checksum.hexdigest() != expected_checksum:
                        raise ValueError("Checksum_Mismatch")
                    destination = directory / f"{incident}_{name}"
                    temporary_path.replace(destination)
                except (OSError, ValueError) as error:
                    reason = str(error) if isinstance(error, ValueError) else "Transfer_IO_Error"
                    print("Attachment download failed:", reason)
                    write_header(outgoing, f"ATTACH_ERROR {rq} {incident} {name} {reason}")
                    return

                # The subscriber successfully received the attachment, saved it to the downloads directory, and sends an ATTACH_OK response to the publisher
                write_header(outgoing, f"ATTACH_OK {rq} {incident} {name}")
                print("Attachment saved:", destination)
    except (OSError, ValueError) as error:
        print("Attachment download failed:", error)
    finally:
        # Cleanup; delete the temporary file if it exists and the download failed
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

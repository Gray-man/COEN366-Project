import hashlib
import ntpath
import os
from pathlib import Path, PureWindowsPath
import socket
from socketserver import StreamRequestHandler, ThreadingTCPServer
import stat
from tempfile import NamedTemporaryFile
from threading import Lock, Thread


TIMEOUT = 5
HEADER_LIMIT = 4096
CHUNK_SIZE = 64 * 1024
is_reserved = getattr(ntpath, "isreserved", lambda name: PureWindowsPath(name).is_reserved())


def valid_file_name(name):
    return (
        bool(name)
        and name not in (".", "..", "NONE")
        and not any(char.isspace() or char in '/\\:<>|?*"\0' for char in name)
        and not name.endswith(".")
        and not is_reserved(name)
    )


def read_header(stream):
    line = stream.readline(HEADER_LIMIT + 1)
    if not line.endswith(b"\n") or len(line) > HEADER_LIMIT:
        raise ValueError("Invalid_Header")
    return line.decode("utf-8").split()


def write_header(stream, message):
    stream.write((message + "\n").encode("utf-8"))
    stream.flush()
    print("TCP sent:", message)


def file_chunks(stream, size):
    while size:
        chunk = stream.read(min(CHUNK_SIZE, size))
        if not chunk:
            raise ValueError("Incomplete_Transfer")
        size -= len(chunk)
        yield chunk


class AttachmentHandler(StreamRequestHandler):
    timeout = TIMEOUT

    def handle(self):
        try:
            fields = read_header(self.rfile)
            print("TCP received:", " ".join(fields))
            if len(fields) != 5 or fields[0] != "GET_ATTACHMENT":
                return
            _, rq, subscriber, incident, name = fields
            if not rq.isdecimal() or not valid_file_name(name):
                write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} Invalid_Request")
                return

            with self.server.attachments_lock:
                published_name = self.server.attachments.get(incident)
            if published_name != name:
                write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} Unknown_Attachment")
                return

            path = (self.server.directory / name).resolve()
            if path.parent != self.server.directory or not path.is_file():
                write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} File_Unavailable")
                return
            try:
                file = path.open("rb")
            except OSError:
                write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} File_Unavailable")
                return

            with file:
                info = os.fstat(file.fileno())
                if not stat.S_ISREG(info.st_mode):
                    write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} File_Unavailable")
                    return
                size = info.st_size
                checksum = hashlib.sha256()
                try:
                    for chunk in file_chunks(file, size):
                        checksum.update(chunk)
                except (OSError, ValueError):
                    write_header(self.wfile, f"ATTACH_ERROR {rq} {incident} {name} File_Unavailable")
                    return
                file.seek(0)
                write_header(self.wfile, f"ATTACH_DATA {rq} {incident} {name} {size} {checksum.hexdigest()}")
                for chunk in file_chunks(file, size):
                    self.wfile.write(chunk)

            result = read_header(self.rfile)
            print(f"TCP received from {subscriber}:", " ".join(result))
        except (OSError, ValueError) as error:
            print("TCP attachment service:", error)


class AttachmentServer(ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, address):
        self.directory = Path.cwd().resolve()
        self.attachments = {}
        self.attachments_lock = Lock()
        super().__init__(address, AttachmentHandler)

    def start(self):
        Thread(target=self.serve_forever, daemon=True).start()
        print(f"Listening for attachments on TCP port {self.server_address[1]}")

    def stop(self):
        self.shutdown()
        self.server_close()


def download_attachment(endpoint, rq, subscriber, incident, name):
    if not valid_file_name(name) or not valid_file_name(incident):
        print("Attachment download failed: Invalid_File_Name")
        return

    identity = [str(rq), incident, name]
    temporary_path = None
    try:
        with socket.create_connection(endpoint, timeout=TIMEOUT) as connection:
            with connection.makefile("rb") as incoming, connection.makefile("wb") as outgoing:
                write_header(outgoing, f"GET_ATTACHMENT {rq} {subscriber} {incident} {name}")
                header = read_header(incoming)
                print("TCP received:", " ".join(header))
                if len(header) == 5 and header[0] == "ATTACH_ERROR" and header[1:4] == identity:
                    return
                try:
                    if len(header) != 6 or header[:4] != ["ATTACH_DATA", *identity]:
                        raise ValueError("Unexpected_Response")
                    size_text, expected_checksum = header[4:]
                    if not size_text.isdecimal():
                        raise ValueError("Invalid_File_Size")
                    size = int(size_text)
                    checksum = hashlib.sha256()
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

                write_header(outgoing, f"ATTACH_OK {rq} {incident} {name}")
                print("Attachment saved:", destination)
    except (OSError, ValueError) as error:
        print("Attachment download failed:", error)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

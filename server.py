
import socket
import ipaddress
import json
import os
import threading
import time

# Server configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
SERVER_TCP_PORT = 6000

# Reliable delivery (section 2.5): seconds to wait for an ALERT_ACK before
# retransmitting, and the total number of transmissions per message.
# The timeout can be changed with the CENRS_ACK_TIMEOUT environment variable.
ACK_TIMEOUT = float(os.environ.get("CENRS_ACK_TIMEOUT", "3"))
MAX_ATTEMPTS = 3

categories = ["FIRE", "SECURITY", "WEATHER", "POWER", "BUILDING", "GENERAL", "ALL"]
locations = ["HALL", "EV", "JMSB", "LOYOLA", "SGW", "ALL"]


# ---------------------------------------------------------------------------
# Section 4 - Persistence and crash recovery
# ---------------------------------------------------------------------------
# All server state lives in two JSON files that are rewritten after every change:
#   users.json     - user profiles (role, IP, ports) and subscriptions
#   incidents.json - incidents (version, status, attachment name + publisher),
#                    status reports and per-version delivery/ACK records
# Nothing else needs saving: the next Incident_ID and server RQ# are derived
# from these files when the server starts.

USERS_FILE = "users.json"
INCIDENTS_FILE = "incidents.json"


def save_json(path, data):
    # Write to a temporary file and then rename it, so a crash in the middle of
    # a save can never leave a half-written file behind: after a crash the file
    # holds either the old state or the new state, never a mix.
    temp_path = path + ".tmp"
    with open(temp_path, "w") as file:
        json.dump(data, file, indent=4)
        file.flush()
        os.fsync(file.fileno())  # make sure the bytes are on disk before the rename
    for _ in range(5):
        try:
            os.replace(temp_path, path)
            return
        except PermissionError:
            # Windows refuses the rename while another program has the file open.
            time.sleep(0.05)
    print("Error: could not save", path)


def load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as file:
            data = json.load(file)
        if not isinstance(data, dict):
            raise ValueError("top level is not a JSON object")
        return data
    except (OSError, ValueError) as error:  # json.JSONDecodeError is a ValueError
        # Keep the damaged file for inspection instead of crashing or overwriting it.
        backup = path + ".corrupt"
        print("Warning: could not read", path, "(" + str(error) + "), moved it to", backup)
        try:
            os.replace(path, backup)
        except OSError:
            pass
        return {}


def save_users():
    save_json(USERS_FILE, users)


def load_users():
    saved_users = load_json(USERS_FILE)
    for user in saved_users.values():
        # JSON has no tuples, subscriptions come back as lists
        user["subscriptions"] = [tuple(subscription) for subscription in user.get("subscriptions", [])]
        user.setdefault("messages_sent", 0)  # older records were saved without it
    return saved_users


def save_incidents():
    save_json(INCIDENTS_FILE, incidents)


def load_incidents():
    return load_json(INCIDENTS_FILE)


users = load_users()
incidents = load_incidents()
# Continue numbering after the incidents already saved, so a restarted server
# never reuses an Incident_ID.
incident_counter = max(
    [int(incident_id[3:]) for incident_id in incidents if incident_id[3:].isdigit()],
    default=0
)
# Same for the RQ# of server-generated notifications: every one of them is saved
# in a delivery record, so continue after the largest one. This keeps a late
# ALERT_ACK from before the crash from matching a new message.
request_counter = max(
    [int(delivery["rq"])
     for incident in incidents.values()
     for version_deliveries in incident.get("deliveries", {}).values()
     for delivery in version_deliveries.values()
     if str(delivery.get("rq", "")).isdigit()],
    default=0
)

# The main receive loop and the retransmission timers run in different threads,
# so every access to users / incidents / pending_acks happens under this lock.
state_lock = threading.RLock()

# Messages waiting for an ALERT_ACK, keyed by (Name, Incident_ID, Version).
pending_acks = {}

# Create a UDP socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# On Windows, sending to a client that is offline makes the next recvfrom()
# raise ConnectionResetError. Disable that so retransmissions to an offline
# client don't disturb the receive loop.
if hasattr(socket, "SIO_UDP_CONNRESET"):
    server.ioctl(socket.SIO_UDP_CONNRESET, False)

# Bind the socket to the server address
server.bind((SERVER_IP, SERVER_PORT))

print("Emergency Server is running...")

def matches_subscription(user_subscriptions, location, category):
    for sub_location, sub_category in user_subscriptions:
        if (sub_location == location or sub_location == "ALL") and (
            sub_category == category or sub_category == "ALL"
        ):
            return True
    return False

def handle_message(message, address):
    parts = message.split()

    if len(parts) < 2:
        response = "Invalid_Message_Format"

    elif not parts[1].isdigit():
        response = "Invalid_Request_Number"

    else:
        command = parts[0]

        for name in users:
            if users[name]["ip"] == address[0] and users[name]["udp_port"] == address[1]:
                users[name]["messages_sent"] = users[name].get("messages_sent", 0) + 1
                save_users()
                break

        match command:

            case "REGISTER":
                response = register_client(parts, address)  # CHANGED

            case "DE-REGISTER":
                response = deregister_client(parts, address)  # CHANGED

            case "SUBSCRIBE":
                response = subscribe_client(parts, address)

            case "UNSUBSCRIBE":
                response = unsubscribe_client(parts, address)

            case "PUBLISH_ALERT":
                response = publish_alert(parts, address)
            case "ATTACH_REQ":
                response = get_attachment_source(parts, address) # Feature 2.9 (Part A)

            case "ALERT_ACK":
                response = handle_alert_ack(parts, address)

            case "CLOSE_ALERT":
                response = close_alert(parts, address)

            case "UPDATE_ALERT":
                response = update_incident(parts, address)
            case "STATUS_REPORT":
                response = status_report(parts, address) #for feature 2.8

            case _:
                response = "Unknown_command"

    # A handler may return (reply, action) when something has to be sent after
    # the reply, e.g. ALL_CLEAR after ALERT_CLOSED.
    after_reply = None
    if isinstance(response, tuple):
        response, after_reply = response

    # ALERT_ACK has no reply in the protocol.
    if response is not None:
        print("Sending:", response)  # NEW
        print("To:", address)  # NEW

        server.sendto(response.encode("utf-8"), address)

    if after_reply is not None:
        after_reply()


def register_client(message, address):

    if len(message) != 7:
        return "REGISTER-DENIED " + message[1] + " Invalid_Message_Format"

    if message[3] not in ["SUBSCRIBER", "PUBLISHER", "BOTH"]:
        return "REGISTER-DENIED " + message[1] + " Invalid_Role"

    try:
        ipaddress.IPv4Address(message[4])

    except ipaddress.AddressValueError:
        return "REGISTER-DENIED " + message[1] + " Invalid_IP_Address"

    try:
        udp_port = int(message[5])
        tcp_port = int(message[6])

        if not (1 <= udp_port <= 65535):
            return "REGISTER-DENIED " + message[1] + " Invalid_UDP_Port"

        if not (1 <= tcp_port <= 65535):
            return "REGISTER-DENIED " + message[1] + " Invalid_TCP_Port"

    except ValueError:
        return "REGISTER-DENIED " + message[1] + " Invalid_Port"

    if message[4] != address[0] or udp_port != address[1]:
        return "REGISTER-DENIED " + message[1] + " Address_Mismatch"

    if message[2] in users:
        existing = users[message[2]]
        if existing["ip"] == address[0] and existing["udp_port"] == address[1]:
            # same client resending (its REGISTERED reply was probably lost)
            # STEP 6: send back this user's saved count
            return "REGISTERED " + message[1] + " [" + ", ".join(locations) + "] [" + ", ".join(categories) + "] " + str(existing["messages_sent"])
        return "REGISTER-DENIED " + message[1] + " Name_Already_Exists"

    for name in users:
        if users[name]["ip"] == address[0] and users[name]["udp_port"] == address[1]:
            return "REGISTER-DENIED " + message[1] + " Address_In_Use"

    users[message[2]] = {
        "role": message[3],
        "ip": message[4],
        "udp_port": udp_port,
        "tcp_port": tcp_port,
        "subscriptions": [],
        "messages_sent": 1  # STEP 4: new user starts at 1
    }

    save_users()

    return "REGISTERED " + message[1] + " [" + ", ".join(locations) + "] [" + ", ".join(categories) + "] 1"

def deregister_client(message, address):

    if len(message) != 3:
         return "DEREGISTER-DENIED " + message[1] + " Invalid_Message_Format"

    if message[2] not in users:
         return "DEREGISTER-DENIED " + message[1] + " Client_Not_Found"

    if users[message[2]]["ip"] != address[0] or users[message[2]]["udp_port"] != address[1]:
        return "DEREGISTER-DENIED " + message[1] + " Address_Mismatch"

    del users[message[2]]

    save_users()

    return "DEREGISTERED " + message[1] + " " + message[2]


def subscribe_client(message, address):

    if len(message) != 4:
        return "SUBSCRIPTION-DENIED " + message[1] + " Invalid_Message_Format"

    userName = "no user"

    for name in users:
        if users[name]["ip"] == address[0] and users[name]["udp_port"] == address[1]:
            userName = name
            break

    if userName == "no user":
        return "SUBSCRIPTION-DENIED " + message[1] + " Client_Not_Found"

    if users[userName]["role"] not in ["SUBSCRIBER", "BOTH"]:
        return "SUBSCRIPTION-DENIED " + message[1] + " Invalid_Role"

    if message[2] not in locations:
        return "SUBSCRIPTION-DENIED " + message[1] + " Invalid_Location"

    if message[3] not in categories:
        return "SUBSCRIPTION-DENIED " + message[1] + " Invalid_Category"

    if (message[2], message[3]) in users[userName]["subscriptions"]:
        return "SUBSCRIBED " + message[1]

    users[userName]["subscriptions"].append((message[2], message[3]))

    save_users()

    return "SUBSCRIBED " + message[1]


def unsubscribe_client(message, address):

    if len(message) != 4:
        return "UNSUBSCRIPTION-DENIED " + message[1] + " Invalid_Message_Format"

    userName = "no user"

    for name in users:
        if users[name]["ip"] == address[0] and users[name]["udp_port"] == address[1]:
            userName = name
            break

    if userName == "no user":
        return "UNSUBSCRIPTION-DENIED " + message[1] + " Client_Not_Found"

    if (message[2], message[3]) in users[userName]["subscriptions"]:
        users[userName]["subscriptions"].remove((message[2], message[3]))

        save_users()

        return "UNSUBSCRIBED " + message[1]

    else:
        return "UNSUBSCRIPTION-DENIED " + message[1] + " Subscription_Not_Found"


def generate_incident_id():
    global incident_counter
    incident_counter += 1
    return "INC" + str(incident_counter).zfill(3)

def generate_request_id():
    # RQ# must be numeric: ALERT_ACK echoes it back, and handle_message rejects
    # requests whose RQ# is not a number.
    global request_counter
    request_counter += 1
    return str(request_counter)

def publish_alert(message, address):
    global incidents

    if len(message)!=8:
        return "ALERT_DENIED " + message[1] + " Invalid_Message_Format"

    userName = None

    for name in users:
        if users[name]["ip"] == address[0] and users[name]["udp_port"] == address[1]:
            userName = name
            break

    if userName is None:
        return "ALERT_DENIED " + message[1] + " Client_Not_Found"

    if users[userName]["role"] not in ["PUBLISHER", "BOTH"]:
        return "ALERT_DENIED " + message[1] + " Invalid_Role"

    category = message[2]
    location = message[3]
    severity = message[4]

    if category not in categories:
        return "ALERT_DENIED " + message[1] + " Invalid_Category"
    if location not in locations:
        return "ALERT_DENIED " + message[1] + " Invalid_Location"
    if severity not in ["INFO", "WARNING", "CRITICAL"]:
        return "ALERT_DENIED " + message[1] + " Invalid_Severity"

    incident_id = generate_incident_id()
    incidents[incident_id] = {
        "publisher": userName,
        "category": category,
        "location": location,
        "severity": severity,
        "title": message[5],
        "description": message[6],
        "attachment": message[7],
        "version": 1,
        "status": "ACTIVE"
    }

    save_incidents()
    distribute_alert(incident_id)

    return "ALERT_ACCEPTED " + message[1] + " " + incident_id

def update_incident(message, address):
    # UPDATE_ALERT RQ# Incident_ID Severity Title Description
    if len(message) != 6:
        return "UPDATE_ALERT-DENIED " + message[1] + " Invalid_Message_Format"

    user_name = None
    for name, user in users.items():
        if (user["ip"], user["udp_port"]) == address:
            user_name = name
            break

    if user_name is None:
        return "UPDATE_ALERT-DENIED " + message[1] + " Client_Not_Found"

    incident_id = message[2]
    incident = incidents.get(incident_id)

    if incident is None:
        return "UPDATE_ALERT-DENIED " + message[1] + " Invalid_Incident_ID"

    if incident["publisher"] != user_name:
        return "UPDATE_ALERT-DENIED " + message[1] + " Not_Incident_Publisher"

    if incident["status"] != "ACTIVE":
        return "UPDATE_ALERT-DENIED " + message[1] + " Incident_Not_Active"

    severity = message[3]
    if severity not in ["INFO", "WARNING", "CRITICAL"]:
        return "UPDATE_ALERT-DENIED " + message[1] + " Invalid_Severity"

    incident["severity"] = severity
    incident["title"] = message[4]
    incident["description"] = message[5]
    incident["version"] += 1
    save_incidents()

    distribute_updates(incident_id)

    return "ALERT_UPDATED " + message[1] + " " + incident_id + " " + str(incident["version"])

def distribute_updates(incident_id):
    incident = incidents[incident_id]

    for name, user in users.items():
        if user["role"] not in ["SUBSCRIBER", "BOTH"]:
            continue

        if not matches_subscription(
            user["subscriptions"],
            incident["location"],
            incident["category"]
        ):
            continue

        request_number = generate_request_id()
        update_message = (
            "ALERT_UPDATE " +
            request_number + " " +
            incident_id + " " +
            str(incident["version"]) + " " +
            incident["severity"] + " " +
            incident["title"] + " " +
            incident["description"]
        )

        client_address = (user["ip"], user["udp_port"])

        if incident["severity"] == "CRITICAL":
            send_reliable(
                name,
                incident_id,
                incident["version"],
                request_number,
                "ALERT_UPDATE",
                update_message
            )
        else:
            server.sendto(update_message.encode("utf-8"), client_address)
            record_delivery(
                incident_id,
                incident["version"],
                name,
                request_number,
                "ALERT_UPDATE",
                "SENT",
                1
            )

        print("Sending update to:", name)
        print("Message:", update_message)

# Feature 2.9 (Part A): Peer-to-Peer Incident Attachments
def get_attachment_source(message, address):

    # Read the request fields
    request_number = message[1]
    incident_id = message[2] if len(message) >= 3 else "NONE"

    # Prepare the denied response prefix
    denied = f"ATTACH_DENIED {request_number} {incident_id}"

    # Validate that the request has all 4 required fields (command, request_number, incident_id, file_name)
    if len(message) != 4:
        return f"{denied} Invalid_Message_Format"

    # Validate that the request is coming from a registered subscriber (matching IP and UDP port)
    subscriber = next(
        (user for user in users.values() if (user["ip"], user["udp_port"]) == address),
        None,
    )
    if subscriber is None:
        return f"{denied} Client_Not_Found"
    if subscriber["role"] not in ("SUBSCRIBER", "BOTH"):
        return f"{denied} Invalid_Role"

    # Validate that the incident exists and is active
    incident = incidents.get(incident_id)
    if incident is None:
        return f"{denied} Unknown_Incident"
    if incident["status"] != "ACTIVE":
        return f"{denied} Incident_Not_Active"

    # Validate that the incident has an attachment and the requested file name matches the incident's attachment
    file_name = message[3]
    if incident["attachment"] == "NONE" or incident["attachment"] != file_name:
        return f"{denied} Attachment_Not_Found"

    # Validate that the publisher of the incident is registered and has the appropriate role to share the attachment 
    publisher_name = incident["publisher"]
    publisher = users.get(publisher_name)
    if publisher is None or publisher["role"] not in ("PUBLISHER", "BOTH"):
        return f"{denied} Publisher_Unavailable"

    # If all validations pass, return the attachment information to the subscriber
    return (
        f"ATTACH_INFO {request_number} {incident_id} {publisher_name} "
        f"{publisher['ip']} {publisher['tcp_port']} {file_name}"
    )


def distribute_alert(incident_id):

    incident = incidents[incident_id]

    for name in users:

        if users[name]["role"] not in ["SUBSCRIBER", "BOTH"]:
            continue

        subscriptions = users[name]["subscriptions"]

        if matches_subscription(subscriptions, incident["location"], incident["category"]):

            request_number = generate_request_id()

            alert_message = (
                "ALERT " +
                request_number + " " +
                incident_id + " " +
                str(incident["version"]) + " " +
                incident["category"] + " " +
                incident["location"] + " " +
                incident["severity"] + " " +
                incident["title"] + " " +
                incident["description"] + " " +
                incident["attachment"]
            )

            client_address = (
                users[name]["ip"],
                users[name]["udp_port"]
            )

            if incident["severity"] == "CRITICAL":
                # Section 2.5: CRITICAL alerts must be acknowledged.
                send_reliable(name, incident_id, incident["version"],
                              request_number, "ALERT", alert_message)
            else:
                server.sendto(alert_message.encode("utf-8"), client_address)
                record_delivery(incident_id, incident["version"], name,
                                request_number, "ALERT", "SENT", 1)

                print("Sending alert to:", name)
                print("Message:", alert_message)


# ---------------------------------------------------------------------------
# Section 2.5 - Reliable delivery of CRITICAL alerts (and ALL_CLEAR)
# ---------------------------------------------------------------------------

def record_delivery(incident_id, version, name, request_number, message_type, status, attempts,
                    message=None):
    # Delivery status is saved per incident and version so it survives a restart:
    # incidents[id]["deliveries"]["<version>"]["<name>"] = {...}
    record = {
        "type": message_type,
        "rq": request_number,
        "status": status,       # SENT, PENDING, CONFIRMED, UNCONFIRMED or SUPERSEDED
        "attempts": attempts
    }
    if message is not None:
        # Messages that need an ACK keep their exact text, so a restarted server
        # can retransmit the same message (same RQ#) - see resume_pending_deliveries.
        record["message"] = message
    deliveries = incidents[incident_id].setdefault("deliveries", {})
    deliveries.setdefault(str(version), {})[name] = record
    save_incidents()


def get_delivery(incident_id, version, name):
    return incidents.get(incident_id, {}).get("deliveries", {}).get(str(version), {}).get(name)


def send_reliable(name, incident_id, version, request_number, message_type, message):
    # Send a message that needs an ALERT_ACK and start its retransmission timer.
    # Each message has its own timer, so several can be waiting at once and the
    # receive loop is never blocked.
    with state_lock:
        # A newer version replaces an older one that is still being retransmitted.
        for key in list(pending_acks):
            if key[0] == name and key[1] == incident_id and key[2] < version:
                timer = pending_acks.pop(key)["timer"]
                if timer is not None:
                    timer.cancel()
                old = get_delivery(incident_id, key[2], name)
                if old is not None:
                    old["status"] = "SUPERSEDED"
                print("Stopped retransmitting", incident_id, "version", key[2], "to", name,
                      "(replaced by version", str(version) + ")")

        address = (users[name]["ip"], users[name]["udp_port"])
        pending_acks[(name, incident_id, version)] = {
            "rq": request_number,
            "message": message,
            "address": address,
            "attempts": 0,
            "timer": None
        }
        record_delivery(incident_id, version, name, request_number, message_type, "PENDING", 0, message)
        transmit(name, incident_id, version)


def transmit(name, incident_id, version):
    entry = pending_acks[(name, incident_id, version)]
    entry["attempts"] += 1

    server.sendto(entry["message"].encode("utf-8"), entry["address"])
    print("Sending to " + name + " (attempt " + str(entry["attempts"]) + "/" + str(MAX_ATTEMPTS) + "):",
          entry["message"])

    delivery = get_delivery(incident_id, version, name)
    if delivery is not None:
        delivery["attempts"] = entry["attempts"]
        save_incidents()

    timer = threading.Timer(ACK_TIMEOUT, on_ack_timeout, args=(name, incident_id, version))
    timer.daemon = True
    entry["timer"] = timer
    timer.start()


def on_ack_timeout(name, incident_id, version):
    with state_lock:
        entry = pending_acks.get((name, incident_id, version))
        if entry is None:
            return  # the ACK arrived just before the timer fired

        if entry["attempts"] < MAX_ATTEMPTS:
            print("No ALERT_ACK from", name, "for", incident_id, "version", version,
                  "after", ACK_TIMEOUT, "s, retransmitting")
            transmit(name, incident_id, version)
            return

        del pending_acks[(name, incident_id, version)]
        delivery = get_delivery(incident_id, version, name)
        if delivery is not None:
            delivery["status"] = "UNCONFIRMED"
            save_incidents()
        print("Delivery of", incident_id, "version", version, "to", name,
              "is UNCONFIRMED after", MAX_ATTEMPTS, "attempts")


def handle_alert_ack(message, address):
    # ALERT_ACK RQ# Incident_ID Version Name
    # The protocol has no reply to an ACK, so this always returns None.
    if len(message) != 5 or not message[3].isdigit():
        print("Ignoring malformed ALERT_ACK")
        return None

    request_number, incident_id, version, name = message[1], message[2], int(message[3]), message[4]

    if name not in users or users[name]["ip"] != address[0] or users[name]["udp_port"] != address[1]:
        print("Ignoring ALERT_ACK: sender is not the registered client", name)
        return None

    entry = pending_acks.get((name, incident_id, version))

    if entry is not None:
        if entry["rq"] != request_number:
            print("Ignoring ALERT_ACK from", name, "for", incident_id, "version", version,
                  "with RQ#", request_number, "(expected " + entry["rq"] + ")")
            return None

        entry["timer"].cancel()
        del pending_acks[(name, incident_id, version)]
        delivery = get_delivery(incident_id, version, name)
        if delivery is not None:
            delivery["status"] = "CONFIRMED"
            save_incidents()
        print("Delivery of", incident_id, "version", version, "to", name,
              "CONFIRMED after", entry["attempts"], "attempt(s)")
        return None

    delivery = get_delivery(incident_id, version, name)

    if delivery is None or delivery["rq"] != request_number:
        print("Ignoring ALERT_ACK from", name, "for", incident_id, "version", version,
              ": no matching message was sent")
    elif delivery["status"] == "CONFIRMED":
        print("Duplicate ALERT_ACK from", name, "for", incident_id, "version", version, "ignored")
    elif delivery["status"] == "UNCONFIRMED":
        # The client did get the message, its ACKs were just late or lost.
        delivery["status"] = "CONFIRMED"
        save_incidents()
        print("Late ALERT_ACK from", name, "for", incident_id, "version", version,
              ": status changed from UNCONFIRMED to CONFIRMED")
    else:
        print("ALERT_ACK from", name, "for", incident_id, "version", version,
              "ignored (status " + delivery["status"] + ")")

    return None


# ---------------------------------------------------------------------------
# Section 2.7 - Closing an incident and ALL_CLEAR
# ---------------------------------------------------------------------------

def close_alert(message, address):
    # CLOSE_ALERT RQ# Incident_ID Reason
    if len(message) != 4:
        return "CLOSE_DENIED " + message[1] + " Invalid_Message_Format"

    userName = None

    for name in users:
        if users[name]["ip"] == address[0] and users[name]["udp_port"] == address[1]:
            userName = name
            break

    if userName is None:
        return "CLOSE_DENIED " + message[1] + " Client_Not_Found"

    incident_id = message[2]

    if incident_id not in incidents:
        return "CLOSE_DENIED " + message[1] + " Unknown_Incident"

    incident = incidents[incident_id]

    if incident["publisher"] != userName:
        return "CLOSE_DENIED " + message[1] + " Not_Incident_Publisher"

    if incident["status"] == "CLOSED":
        return "CLOSE_DENIED " + message[1] + " Incident_Already_Closed"

    incident["status"] = "CLOSED"
    incident["version"] += 1
    incident["close_reason"] = message[3]
    save_incidents()

    # Reply ALERT_CLOSED first, then send ALL_CLEAR to the subscribers.
    return ("ALERT_CLOSED " + message[1] + " " + incident_id,
            lambda: distribute_all_clear(incident_id))


def distribute_all_clear(incident_id):
    # ALL_CLEAR goes to every subscriber that received this incident, plus every
    # subscriber that currently matches it. It always needs an ALERT_ACK.
    incident = incidents[incident_id]

    recipients = set()
    for version_deliveries in incident.get("deliveries", {}).values():
        recipients.update(version_deliveries)

    for name in users:
        if users[name]["role"] in ["SUBSCRIBER", "BOTH"] and matches_subscription(
            users[name]["subscriptions"], incident["location"], incident["category"]
        ):
            recipients.add(name)

    for name in sorted(recipients):
        if name not in users:
            continue  # de-registered since it received the alert

        request_number = generate_request_id()
        all_clear_message = (
            "ALL_CLEAR " +
            request_number + " " +
            incident_id + " " +
            str(incident["version"]) + " " +
            incident["close_reason"]
        )
        send_reliable(name, incident_id, incident["version"],
                      request_number, "ALL_CLEAR", all_clear_message)


#Section 2.8: User Safety/Response Status (UDP)(Feature 2.8)
def status_report(message, address):
    # STATUS_REPORT RQ# INCIDENT_ID Name Status
    if len(message) !=5:
        return "STATUS_REJECTED " + message[1] + " Invalid_Message_Format"

    incident_id = message[2]
    name = message[3]
    status = message[4]

    if name not in users:
        return "STATUS_REJECTED " + message[1] + " Client_Not_Found"

    if users[name]["ip"] != address[0] or users[name]["udp_port"] != address[1]:
        return "STATUS_REJECTED " + message[1] + " Address_Mismatch"

    if incident_id not in incidents:
        return "STATUS_REJECTED " + message[1] + " Unknown_Incident"

    if incidents[incident_id]["status"] == "CLOSED":
        return "STATUS_REJECTED " + message[1] + " Incident_Closed"

    if status not in ["SAFE", "NEED_HELP", "LEFT_AREA"]:
        return "STATUS_REJECTED " + message[1] + " Invalid_Status"

    incident = incidents[incident_id]
    if "status_reports" not in incident:
        incident["status_reports"] = {}
    incident["status_reports"][name] = status
    save_incidents()

    print("Status report received from", name, "for", incident_id, ":", status)
    return "STATUS_RECORDED " + message[1]

#Section 2.10: Recovering current emergency information (TCP)

def get_active_alerts(message,address):
    #Get_ACTIVE_ALERTS RQ # Name
    if len(message) != 3 or message[0] != "GET_ACTIVE_ALERTS" or not message[1].isdigit():
        request_number = message[1] if len(message) > 1 else "0"
        return "ACTIVE_ALERTS_DENIED " + request_number + " Invalid_Message_Format"

    request_number = message[1]
    name = message[2]

    if name not in users:
        return "ACTIVE_ALERTS_DENIED " + request_number + " Client_Not_Found"

    if users[name]["ip"] != address[0]:
        return "ACTIVE_ALERTS_DENIED " + request_number + " Address_Mismatch"

    # Keep only ACTIVE incidents that match this client's subscriptions
    records = []
    for incident_id, incident in incidents.items():
        if incident["status"] != "ACTIVE":
            continue
        if not matches_subscription(users[name]["subscriptions"], incident["location"], incident["category"]):
            continue

        # One record per line: ID Version Category Location Severity Status Title Description Attachment
        record = (
            incident_id + " " +
            str(incident["version"]) + " " +
            incident["category"] + " " +
            incident["location"] + " " +
            incident["severity"] + " " +
            incident["status"] + " " +
            incident["title"] + " " +
            incident["description"] + " " +
            incident["attachment"]
        )
        records.append(record)

    # Header line with the number of records, then one line per record
    reply = "ACTIVE_ALERTS " + request_number + " " + str(len(records)) + "\n"
    for record in records:
        reply += record + "\n"
    return reply

def handle_tcp_client(connection, address):
    # Runs in its own thread, so a slow TCP client never blocks the UDP loop
    with connection:
        connection.settimeout(5)
        try:
            with connection.makefile("r", encoding="utf-8") as incoming:
                line = incoming.readline()
            print("TCP received:", line.strip())
            print("From:", address)

            with state_lock:
                reply = get_active_alerts(line.split(), address)

            connection.sendall(reply.encode("utf-8"))
            print("TCP sent:", reply.strip())
        except OSError as error:
            print("TCP sync error:", error)


def tcp_listener():
    # Accepts TCP connections and starts a new thread for each client
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        tcp_server.bind((SERVER_IP, SERVER_TCP_PORT))
    except OSError as error:
        print("Cannot start TCP sync on port", SERVER_TCP_PORT, ":", error)
        return

    tcp_server.listen()
    print("Listening for TCP sync on port", SERVER_TCP_PORT)

    while True:
        connection, address = tcp_server.accept()
        threading.Thread(target=handle_tcp_client, args=(connection, address), daemon=True).start()


# ---------------------------------------------------------------------------
# Section 4 - Crash recovery at startup
# ---------------------------------------------------------------------------

def resume_pending_deliveries():
    # Timers do not survive a crash, so a delivery that was still waiting for an
    # ALERT_ACK is left as PENDING in incidents.json. Each one is finished here:
    #   - older version than the incident's current one -> SUPERSEDED
    #   - recipient de-registered, all attempts used, or
    #     no saved message text                        -> UNCONFIRMED
    #   - otherwise -> retransmitted with the same RQ# and the attempts that are
    #     left. The client sees a duplicate (Incident_ID, Version), ACKs it again
    #     and does not show it twice.
    resumed = 0
    for incident_id, incident in incidents.items():
        for version_text, version_deliveries in incident.get("deliveries", {}).items():
            for name, delivery in version_deliveries.items():
                if delivery.get("status") != "PENDING":
                    continue
                version = int(version_text)

                if version < incident["version"]:
                    delivery["status"] = "SUPERSEDED"
                elif (name not in users or "message" not in delivery
                      or delivery.get("attempts", 0) >= MAX_ATTEMPTS):
                    delivery["status"] = "UNCONFIRMED"
                else:
                    pending_acks[(name, incident_id, version)] = {
                        "rq": delivery["rq"],
                        "message": delivery["message"],
                        "address": (users[name]["ip"], users[name]["udp_port"]),
                        "attempts": delivery.get("attempts", 0),
                        "timer": None
                    }
                    resumed += 1
                    continue
                print("Recovery:", delivery["type"], incident_id, "version", version, "to", name,
                      "->", delivery["status"])
    save_incidents()

    for name, incident_id, version in list(pending_acks):
        print("Recovery: resuming", get_delivery(incident_id, version, name)["type"], incident_id,
              "version", version, "to", name)
        transmit(name, incident_id, version)
    return resumed


def print_recovery_summary():
    active = sum(1 for incident in incidents.values() if incident["status"] == "ACTIVE")
    with_attachment = sum(1 for incident in incidents.values() if incident.get("attachment", "NONE") != "NONE")
    reports = sum(len(incident.get("status_reports", {})) for incident in incidents.values())
    delivery_counts = {}
    for incident in incidents.values():
        for version_deliveries in incident.get("deliveries", {}).values():
            for delivery in version_deliveries.values():
                delivery_counts[delivery["status"]] = delivery_counts.get(delivery["status"], 0) + 1

    print("Recovered from disk:")
    print("  users:", len(users), "(" + str(sum(len(u["subscriptions"]) for u in users.values())),
          "subscriptions)")
    print("  incidents:", len(incidents), "(" + str(active), "active,", len(incidents) - active, "closed,",
          with_attachment, "with attachment)")
    print("  status reports:", reports)
    print("  delivery records:", delivery_counts if delivery_counts else "none")
    print("  next Incident_ID: INC" + str(incident_counter + 1).zfill(3),
          "| next server RQ#:", request_counter + 1)


with state_lock:
    print_recovery_summary()
    resume_pending_deliveries()

# Start the TCP listener in the background (Section 2.10)
threading.Thread(target=tcp_listener, daemon=True).start()

# Keep server running
while True:
    try:
        data, address = server.recvfrom(4096)

        message = data.decode("utf-8")

        print("Received:", message)
        print("From:", address)

        with state_lock:
            handle_message(message, address)

    except Exception as e:
        print("Error:", e)

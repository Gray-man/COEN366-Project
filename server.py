
import socket
import ipaddress
import json
import os
import threading
import time

# Server configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

# Reliable delivery (section 2.5): seconds to wait for an ALERT_ACK before
# retransmitting, and the total number of transmissions per message.
# The timeout can be changed with the CENRS_ACK_TIMEOUT environment variable.
ACK_TIMEOUT = float(os.environ.get("CENRS_ACK_TIMEOUT", "3"))
MAX_ATTEMPTS = 3

categories = ["FIRE", "SECURITY", "WEATHER", "POWER", "BUILDING", "GENERAL", "ALL"]
locations = ["HALL", "EV", "JMSB", "LOYOLA", "SGW", "ALL"]


def save_users():
    with open("users.json", "w") as file:
        json.dump(users, file, indent=4)



def load_users():
    if os.path.exists("users.json"):
        with open("users.json", "r") as file:
            saved_users = json.load(file)

        for name in saved_users:
            saved_users[name]["subscriptions"] = [
                tuple(subscription)
                for subscription in saved_users[name]["subscriptions"]
            ]

        return saved_users

    return {}

def save_incidents():
    # Write to a temporary file and then rename it, so a crash in the middle of
    # a save can never leave a half-written incidents.json behind.
    with open("incidents.json.tmp", "w") as file:
        json.dump(incidents, file, indent=4)
    for _ in range(5):
        try:
            os.replace("incidents.json.tmp", "incidents.json")
            return
        except PermissionError:
            # Windows refuses the rename while another program has the file open.
            time.sleep(0.05)
    print("Error: could not save incidents.json")

def load_incidents():
    if os.path.exists("incidents.json"):
        with open("incidents.json", "r") as file:
            saved_incidents = json.load(file)
        return saved_incidents
    return {}


users = load_users()
incidents = load_incidents()
# Continue numbering after the incidents already saved, so a restarted server
# never reuses an Incident_ID.
incident_counter = max(
    [int(incident_id[3:]) for incident_id in incidents if incident_id[3:].isdigit()],
    default=0
)
request_counter = 0

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

            case "ALERT_ACK":
                response = handle_alert_ack(parts, address)

            case "CLOSE_ALERT":
                response = close_alert(parts, address)

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
        return "ALERT-DENIED " + message[1] + " Invalid_Message_Format"

    userName = None

    for name in users:
        if users[name]["ip"] == address[0] and users[name]["udp_port"] == address[1]:
            userName = name
            break

    if userName is None:
        return "ALERT-DENIED " + message[1] + " Client_Not_Found"

    if users[userName]["role"] not in ["PUBLISHER", "BOTH"]:
        return "ALERT-DENIED " + message[1] + " Invalid_Role"

    category = message[2]
    location = message[3]
    severity = message[4]

    if category not in categories:
        return "ALERT-DENIED " + message[1] + " Invalid_Category"
    if location not in locations:
        return "ALERT-DENIED " + message[1] + " Invalid_Location"
    if severity not in ["INFO", "WARNING", "CRITICAL"]:
        return "ALERT-DENIED " + message[1] + " Invalid_Severity"

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

def record_delivery(incident_id, version, name, request_number, message_type, status, attempts):
    # Delivery status is saved per incident and version so it survives a restart:
    # incidents[id]["deliveries"]["<version>"]["<name>"] = {...}
    deliveries = incidents[incident_id].setdefault("deliveries", {})
    deliveries.setdefault(str(version), {})[name] = {
        "type": message_type,
        "rq": request_number,
        "status": status,       # SENT, PENDING, CONFIRMED, UNCONFIRMED or SUPERSEDED
        "attempts": attempts
    }
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
                pending_acks.pop(key)["timer"].cancel()
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
        record_delivery(incident_id, version, name, request_number, message_type, "PENDING", 0)
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
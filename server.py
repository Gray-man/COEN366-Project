
import socket
import ipaddress
import json
import os

# Server configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

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
    with open("incidents.json", "w") as file:
        json.dump(incidents, file, indent=4)

def load_incidents():
    if os.path.exists("incidents.json"):
        with open("incidents.json", "r") as file:
            saved_incidents = json.load(file)
        return saved_incidents
    return {}


users = load_users()
incidents = load_incidents()
incident_counter = 0
request_counter = 0

# Create a UDP socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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

            case _:
                response = "Unknown_command"

    print("Sending:", response)  # NEW
    print("To:", address)  # NEW

    server.sendto(response.encode("utf-8"), address)


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
            return "REGISTERED " + message[1] + " [" + ", ".join(locations) + "] [" + ", ".join(categories) + "]"
        return "REGISTER-DENIED " + message[1] + " Name_Already_Exists"

    for name in users:
        if users[name]["ip"] == address[0] and users[name]["udp_port"] == address[1]:
            return "REGISTER-DENIED " + message[1] + " Address_In_Use"

    users[message[2]] = {
        "role": message[3],
        "ip": message[4],
        "udp_port": udp_port,
        "tcp_port": tcp_port,
        "subscriptions": []
    }

    save_users()

    return "REGISTERED " + message[1] + " [" + ", ".join(locations) + "] [" + ", ".join(categories) + "]"

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
    global request_counter
    request_counter += 1
    return "REQ" + str(request_counter).zfill(3)

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

            server.sendto(alert_message.encode("utf-8"), client_address)

            print("Sending alert to:", name)
            print("Message:", alert_message)






# Keep server running
while True:
    try:
        data, address = server.recvfrom(4096)

        message = data.decode("utf-8")

        print("Received:", message)
        print("From:", address)

        handle_message(message, address)

    except Exception as e:
        print("Error:", e)
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
from flask import Flask, render_template, request, redirect, url_for
import json
from mongoengine import *
import paho.mqtt.client as mqtt
import itertools

# MongoDB Documents
class Data(EmbeddedDocument):
    temperature = FloatField()
    humidity = FloatField()

class Info(Document):
    device_id = IntField()
    timestamp = FloatField()
    data = EmbeddedDocumentField(Data)

class Platform:
    id_iter = itertools.count()
    
    # Pre-shared key for HMAC DH key exchanges with keyboard devices
    devices_passwords = [] # {"id" : 1, "password" : "1234".encode('utf-8')}

    # Shared keys for AES encryption with all devices
    devices = [] # {"id" : 1, "shared_key" : b'1234', "type" : "0"}

    topics = ["seguridadiot/device/sensor"]

    # Pre-shared key for HMAC DH key exchange (default value for not keyboard devices)
    hmac_shared_key = 'securitygroupd'.encode('utf-8')

    def hmac_dh_step(self, message):
        parameters = message["info"]["parameters"]
        remote_public_key = message["info"]["public_key"]
        signature = bytes.fromhex(message["hmac"])

        # Load default pre-shared key
        preshared_key = self.hmac_shared_key

        # Check if the device is a keyboard device added to platform
        for device in self.devices_passwords:
            if device["id"] == message["info"]["id"]:
                preshared_key = device["password"].encode('utf-8')

        # Check if the signature is valid
        h = hmac.HMAC(preshared_key, hashes.SHA256())
        h.update(json.dumps(message["info"]).encode('utf-8'))

        if h.finalize() != signature:
            print("Signature is not valid")
            return None
    
        # Get DH parameters and device public key, generate private and public keys
        parameters_numbers = dh.DHParameterNumbers(
            parameters["p"], parameters["g"], parameters["q"])
        parameters = parameters_numbers.parameters()
        remote_public_key = dh.DHPublicNumbers(
            remote_public_key, parameters_numbers).public_key()

        local_private_key = parameters.generate_private_key()
        local_public_key = local_private_key.public_key()

        # Derive shared key
        shared_key = local_private_key.exchange(remote_public_key)

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
        )

        # Create or update shared key for the device
        find = False
        for device in self.devices:
            if device["id"] == message["info"]["id"]:
                device["shared_key"] = kdf.derive(shared_key)
                find = True

        if not find:
            self.devices.append({"id": message["info"]["id"], "shared_key": kdf.derive(
                shared_key), "type": message["info"]["type"]})

        # Generate DH response with platform public key
        info = {
            "id": message["info"]["id"],
            "public_key": local_public_key.public_numbers().y
        }

        # Generate HMAC signature
        h = hmac.HMAC(preshared_key, hashes.SHA256())
        h.update(json.dumps(info).encode('utf-8'))

        signature = h.finalize()

        message = {
            "info": info,
            "hmac": signature.hex()
        }

        return message


platform = Platform()

# Connection to MQTT broker
def on_connect(client, userdata, flags, rc):
    client.subscribe("seguridadiot/device/connect")
    client.subscribe("seguridadiot/device/sensor")
    print("Platform connected to broker")


def on_message(client, userdata, msg):
    if msg.topic == "seguridadiot/device/connect":
        # If connection request, add it to platform if signature is valid
        message = platform.hmac_dh_step(json.loads(msg.payload))
        if message is not None:
            # Send response to device
            client.publish("seguridadiot/platform/connect", json.dumps(message))
            print("New device connected")

    # If data, decrypt it and save it to MongoDB
    elif msg.topic in platform.topics:
        message = json.loads(msg.payload)

        aad = message["aad"]
        nonce = bytes.fromhex(message["nonce"])
        data = bytes.fromhex(message["data"])

        # Get shared key for the device
        shared_key = None
        for device in platform.devices:
            if device["id"] == aad["id"]:
                shared_key = device["shared_key"]
                break
        
        # Decrypt data with AESGCM or AESOCB3, if no shared key, ignore
        if shared_key is not None:
            if aad["encrypt"] == 0:
                cipher = AESGCM(shared_key)
            elif aad["encrypt"] == 1:
                cipher = AESOCB3(shared_key)


            try: 
                plaintext = cipher.decrypt(
                    nonce, data, json.dumps(aad).encode('utf-8'))
                

                plaintext_json = json.loads(plaintext.decode('utf-8'))
                data = Data(temperature=plaintext_json["temperature"], humidity=plaintext_json["humidity"])
                info = Info(device_id=aad["id"], timestamp=aad["timestamp"], data=data)
                info.save()
            except Exception as e:
                print("Error decrypting data")


# Web server
app = Flask(__name__)
client = mqtt.Client()

@app.route("/")
def index():
    return render_template("devices.html", devices=platform.devices)

@app.route("/devices")
def devices():
    return render_template("devices.html", devices=platform.devices)

@app.route("/passwords",  methods= ["POST", "GET"])
def passwords():
    if request.method == "POST":
        password = request.form.get("password")

        newId = next(platform.id_iter)

        devices = list(filter(lambda device: device["id"] == newId, platform.devices))        
        while len(devices) > 0:
            newId = next(platform.id_iter)
            devices = list(filter(lambda device: device["id"] == newId, platform.devices))

        passwordObj = {
            "id" : newId,
            "password" : password
        }

        platform.devices_passwords.append(passwordObj)
        return redirect(url_for('passwords'))
    return render_template("passwords.html", passwords=platform.devices_passwords)

@app.route("/passwords/delete")
def deletePassword():
    id = request.args.get("id")
    for ps in platform.devices_passwords:
        if ps["id"] == int(id):
            platform.devices_passwords.remove(ps)
            break
    return redirect(url_for('passwords'))

@app.route("/devices/delete")
def deleteDevice():
    id = request.args.get("id")
    for device in platform.devices:
        if device["id"] == int(id):
            platform.devices.remove(device)
            break
    return redirect(url_for('devices'))

@app.route("/messages")
def display_messages():
    return render_template("messages.html", messages = Info.objects().order_by('-timestamp'))

@app.route("/select_messages")
def select_messages():
    return render_template("select_messages.html", messages = Info.objects().order_by('-timestamp'))


if __name__ == "__main__":
    client.on_connect = on_connect
    client.on_message = on_message
    client.username_pw_set("public", "public")
    client.connect("public.cloud.shiftr.io", 1883, 60)

    connect(host="mongodb+srv://admin:admin@icd.6itjtdp.mongodb.net/Seguridad?retryWrites=true&w=majority")

    client.loop_start()
    app.run()
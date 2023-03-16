from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
import json
import paho.mqtt.client as mqtt
import random
import time
import os

class Device:
    device_id = None
    device_type = None
    encryption_algorithm = None

    hmac_shared_key = "1234".encode('utf-8')

    dh_parameters = None

    local_private_key = None
    local_public_key = None

    remote_public_key = None

    shared_key = None

    last_key_negotiation = None
    key_timeout = 60

    data_topic = "seguridadiot/device/sensor"

    send_period = 5


    def __init__(self, device_id, device_type, encryption_algorithm):
        self.device_id = device_id
        self.device_type = device_type
        self.encryption_algorithm = encryption_algorithm


    def first_hmac_dh_step(self):
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.local_private_key = self.dh_parameters.generate_private_key()
        self.local_public_key = self.local_private_key.public_key()

        info = {
            "id" : self.device_id,
            "type" : self.device_type,
            "encryption": self.encryption_algorithm,
            "parameters": {"p": self.dh_parameters.parameter_numbers().p, "g": self.dh_parameters.parameter_numbers().g, "q": self.dh_parameters.parameter_numbers().q},
            "public_key": self.local_public_key.public_numbers().y
        }

        h = hmac.HMAC(self.hmac_shared_key, hashes.SHA256())
        h.update(json.dumps(info).encode('utf-8'))

        signature = h.finalize()

        message = {
            "info": info,
            "hmac": signature.hex()
        }

        return message

    def second_hmac_dh_step(self, message):
        self.remote_public_key = dh.DHPublicNumbers(message["info"]["public_key"], self.dh_parameters.parameter_numbers()).public_key()
        signature = bytes.fromhex(message["hmac"])

        h = hmac.HMAC(self.hmac_shared_key, hashes.SHA256())
        h.update(json.dumps(message["info"]).encode('utf-8'))

        if h.finalize() != signature:
            raise Exception("Signature is not valid")

        shared_key = self.local_private_key.exchange(self.remote_public_key)

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
        )

        self.shared_key = kdf.derive(shared_key)
        self.last_key_negotiation = time.time()


print("Type device id:")
device_id = int(input())

print("Type device type (0 : sensor, 1 : keyboard):")
device_type = int(input())

print("Type device encryption (0 : AESGCM, 1 : AESOCB3):")
encryption_algorithm = int(input())

device = Device(device_id, device_type, encryption_algorithm)

if device_type == 1:
    print("Type platform password:")
    device.hmac_shared_key = input().encode('utf-8')

    print("Type send period (seconds):")
    device.send_period = int(input())

    print("Type key timeout (minutes):")
    device.key_timeout = int(input())

def on_connect(client, userdata, flags, rc):
    print("Connecting to platform...")
    client.subscribe("seguridadiot/platform/connect")
    print("Starting key negotiation...")
    message = device.first_hmac_dh_step()
    client.publish("seguridadiot/device/connect", json.dumps(message))


def on_message(client, userdata, msg):
    message = json.loads(msg.payload)
    if msg.topic == "seguridadiot/platform/connect" and message["info"]["id"] == device.device_id:
        device.second_hmac_dh_step(message)
        print("Key negotiation completed")
        print("Connected to platform")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.username_pw_set("public", "public")

client.connect("public.cloud.shiftr.io", 1883, 60)

client.loop_start()

while True:

    if device.shared_key is not None:

        aad = {
            "id": device.device_id,
            "encrypt": device.encryption_algorithm,
            "timestamp": time.time()
        }

        data = {
            "temperature": random.randrange(0, 30),
            "humidity": random.randrange(0, 100)
        }

        if encryption_algorithm == 0:
            cipher = AESGCM(device.shared_key)
        elif encryption_algorithm == 1:
            cipher = AESOCB3(device.shared_key)

        nonce = os.urandom(12)

        encrypted_data = cipher.encrypt(nonce, json.dumps(data).encode('utf-8'), json.dumps(aad).encode('utf-8'))

        message = {
            "aad": aad,
            "data": encrypted_data.hex(),
            "nonce": nonce.hex()
        }

        client.publish(device.data_topic, json.dumps(message))

        if time.time() - device.last_key_negotiation > device.key_timeout * 60:
            device.shared_key = None
            print("Starting key renegotiation...")
            message = device.first_hmac_dh_step()
            client.publish("seguridadiot/device/connect", json.dumps(message))
        
    time.sleep(device.send_period)
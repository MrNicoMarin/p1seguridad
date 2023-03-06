from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import paho.mqtt.client as mqtt
import random
import time
import os

class Device:
    hmac_shared_key = b'1234'

    dh_parameters = None

    local_private_key = None
    local_public_key = None

    remote_public_key = None

    shared_key = None

    last_key_negotiation = None
    key_timeout = 1


    def first_hmac_dh_step(self):
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.local_private_key = self.dh_parameters.generate_private_key()
        self.local_public_key = self.local_private_key.public_key()

        info = {
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


device = Device()

def on_connect(client, userdata, flags, rc):
    print("Connecting to platform...")
    client.subscribe("nico/device/connect")
    print("Starting key negotiation...")
    message = device.first_hmac_dh_step()
    client.publish("nico/platform/connect", json.dumps(message))


def on_message(client, userdata, msg):
    device.second_hmac_dh_step(json.loads(msg.payload))
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
            "id": 1,
            "timestamp": time.time()
        }

        data = {
            "temperature": random.randrange(0, 30),
            "humidity": random.randrange(0, 100)
        }

        cipher = AESGCM(device.shared_key)

        nonce = os.urandom(12)

        encrypted_data = cipher.encrypt(nonce, json.dumps(data).encode('utf-8'), json.dumps(aad).encode('utf-8'))

        message = {
            "aad": aad,
            "data": encrypted_data.hex(),
            "nonce": nonce.hex()
        }

        client.publish("nico/platform/sensor", json.dumps(message))

        if time.time() - device.last_key_negotiation > device.key_timeout * 60:
            device.shared_key = None
            print("Starting key renegotiation...")
            message = device.first_hmac_dh_step()
            client.publish("nico/platform/connect", json.dumps(message))
        
    time.sleep(1)
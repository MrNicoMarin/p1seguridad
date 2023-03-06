from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import paho.mqtt.client as mqtt

class Platform:

    # Topics: 


    # Plataforma
    # Conectar un nuevo dispositivo -> seguridadiot/device/connect
    # Enviar datos de un sensor -> seguridadiot/device/sensor



    devices = []


    hmac_shared_key = '1234'.encode('utf-8')

    def hmac_dh_step(self, message):
        parameters = message["info"]["parameters"]
        remote_public_key = message["info"]["public_key"]
        signature = bytes.fromhex(message["hmac"])

        h = hmac.HMAC(self.hmac_shared_key, hashes.SHA256())
        h.update(json.dumps(message["info"]).encode('utf-8'))

        if h.finalize() != signature:
            raise Exception("Signature is not valid")
        
        parameters_numbers = dh.DHParameterNumbers(parameters["p"], parameters["g"], parameters["q"])
        parameters = parameters_numbers.parameters()
        remote_public_key = dh.DHPublicNumbers(remote_public_key, parameters_numbers).public_key()

        local_private_key = parameters.generate_private_key()
        local_public_key = local_private_key.public_key()

        shared_key = local_private_key.exchange(remote_public_key)

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
        )

        find = False
        for device in self.devices:
            if device["id"] == message["info"]["id"]:
                device["shared_key"] = kdf.derive(shared_key)
                find = True
            
        if not find:
            self.devices.append({"id" : message["info"]["id"], "shared_key" : kdf.derive(shared_key), "type" : message["info"]["type"]})

        info = {
            "id" : message["info"]["id"],
            "public_key": local_public_key.public_numbers().y
        }

        h = hmac.HMAC(self.hmac_shared_key, hashes.SHA256())
        h.update(json.dumps(info).encode('utf-8'))

        signature = h.finalize()

        message = {
            "info": info,
            "hmac": signature.hex()
        }

        return message


platform = Platform()

def on_connect(client, userdata, flags, rc):
    client.subscribe("seguridadiot/device/connect")
    client.subscribe("seguridadiot/device/sensor")
    print("Platform connected to broker")

def on_message(client, userdata, msg):
    if msg.topic == "seguridadiot/device/connect":
        message = platform.hmac_dh_step(json.loads(msg.payload))
        client.publish("seguridadiot/platform/connect", json.dumps(message))
        print("New device connected")
    
    elif msg.topic == "seguridadiot/device/sensor":
        message = json.loads(msg.payload)

        aad = message["aad"]
        nonce = bytes.fromhex(message["nonce"])
        data = bytes.fromhex(message["data"])

        shared_key = None
        for device in platform.devices:
            if device["id"] == aad["id"]:
                shared_key = device["shared_key"]
                break

        cipher = AESGCM(shared_key)

        plaintext = cipher.decrypt(nonce, data, json.dumps(aad).encode('utf-8'))

        print("Received sensor data: {} and associated data {}".format(plaintext.decode('utf-8'), aad))
        

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.username_pw_set("public", "public")

client.connect("public.cloud.shiftr.io", 1883, 60)

client.loop_forever()
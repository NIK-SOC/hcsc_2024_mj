import requests
from hashlib import sha1, md5
import hmac
from base64 import b64encode
from time import time

url = "http://localhost:7385"
hmac_key = "K7Sx5Io4gYXH4yQTTv25P7NQA9nQnuSq7ifXUiRf"


def sign_hmac(key, msg):
    return b64encode(hmac.new(key.encode(), msg.encode(), sha1).digest())


def md5_hash(msg):
    return md5(msg.encode()).hexdigest()


def gen_signature(
    method, path, responseCode, clientId, version, headers, timestamp, body
):
    msg = f"{method}\n{path}\n{responseCode}\n{version}\n{clientId}\n{md5_hash(headers)}\n{timestamp}\n{md5_hash(body)}"
    return sign_hmac(hmac_key, msg).decode()


def main():
    timestamp = int(time())
    signature = gen_signature(
        "POST",
        "/flag",
        "",
        "hu.honeylab.hcsc.thereott",
        "1.0",
        "x-tott-app-id:hu.honeylab.hcsc.thereott,x-tott-app-name:thereott",
        timestamp,
        "flag",
    )
    headers = {
        "x-tott-app-id": "hu.honeylab.hcsc.thereott",
        "x-tott-app-name": "ThereOtt",
        "x-timestamp": str(timestamp),
        "x-signature": signature,
    }
    r = requests.post(url + "/flag", data="flag", headers=headers)
    print(r.text)


if __name__ == "__main__":
    main()

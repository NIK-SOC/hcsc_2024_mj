import csv
import os
import json
import base64
import hashlib
import requests


host = "http://localhost:8080"


def sha256sum(filename):
    hash_sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hash_sha256.update(byte_block)
    return hash_sha256.hexdigest()


subspecies_to_filter = [
    "Carniolan honey bee",
    "Italian honey bee",
    "Russian honey bee",
    "VSH Italian honey bee",
    "Western honey bee",
]

bee_data = {}
with open("assets/bee_data.csv", newline="") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        if row["subspecies"] in subspecies_to_filter:
            bee_data[row["file"]] = {
                "subspecies": row["subspecies"],
            }

image_hashes = {}
for filename in os.listdir("assets/bee_imgs"):
    if filename in bee_data:
        filepath = os.path.join("assets/bee_imgs", filename)
        image_hash = sha256sum(filepath)
        image_hashes[filename] = image_hash

response = requests.get(f"{host}/images")
image_data = json.loads(response.text)

submission_data = {}
for item in image_data:
    for identifier, base64_data in item.items():
        image_data = base64.b64decode(base64_data)
        image_hash = hashlib.sha256(image_data).hexdigest()
        filename = None
        for key, value in image_hashes.items():
            if value == image_hash:
                filename = key
                break
        if not filename:
            raise Exception(f"Could not find filename for hash {image_hash}")
        subspecie = bee_data[filename]["subspecies"]
        submission_data[identifier] = subspecie

print(submission_data)

response = requests.post(f"{host}/submit", json=submission_data)
print()
print(response.text)

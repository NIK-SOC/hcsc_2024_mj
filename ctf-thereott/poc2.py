import requests
import frida
import time

url = "http://localhost:7385"


def generate_signature():
    script_code = """
    const targetClass = 'hu.honeylab.hcsc.thereott.UtilsJNI';

    send({ type: 'script_start', message: 'Frida script started' });

    Java.perform(function() {
        const utilsJNI = Java.use(targetClass);

        utilsJNI.genSignature.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(method, path, responseStatus, headers, body, timestamp) {
            const signature = this.genSignature(
                "POST",
                "/flag",
                "",
                "x-tott-app-id:hu.honeylab.hcsc.thereott,x-tott-app-name:thereott",
                "flag",
                timestamp
            );

            send({ type: 'send', signature: signature, timestamp: timestamp });
            
            return signature;
        };
    });
    """

    device = frida.get_usb_device()
    pid = device.spawn(["hu.honeylab.hcsc.thereott"])
    session = device.attach(pid)

    def on_message(message, payload):
        if message["payload"]["type"] == "script_start":
            print(message["payload"])
        elif message["payload"]["type"] == "send":
            print(message)
            signature = message["payload"]["signature"]
            timestamp = message["payload"]["timestamp"]
            send_request(signature, timestamp)

    script = session.create_script(script_code)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    time.sleep(5)  # increase this if your device is slow


def send_request(signature, timestamp):
    flag_url = url + "/flag"

    headers = {
        "x-tott-app-id": "hu.honeylab.hcsc.thereott",
        "x-tott-app-name": "ThereOtt",
        "x-timestamp": timestamp,
        "x-signature": signature,
    }

    response = requests.post(flag_url, headers=headers, data="flag")
    print("Flag: ", response.text)


def main():
    generate_signature()


if __name__ == "__main__":
    main()

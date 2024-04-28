import requests

url = "http://replacehost:replaceport"

def main():
    r = requests.post(url + "/flag", data="flag")
    print(r.text)

if __name__ == "__main__":
    main()
import requests
# HUN paraszt pwntools / ENG peasant pwntools :)
from json import loads

url = "http://localhost:8080"

# aflj lists all functions in JSON format and h does seemingly nothing,
# but we need to supply a second command
data = {"command1": "aflj", "argument1": "", "command2": "h", "argument2": ""}

response = requests.post(url, data=data)
response = response.text.split("Output:\n")[1].split("\n")[0]
response = loads(response)

function_address = None
for function_info in response:
    if (
        function_info.get("codexrefs") == None
        and function_info.get("dataxrefs")
        == None  # hacky way to find functions with no xrefs
        and function_info["name"].startswith("fcn.")
    ):
        function_address = function_info["offset"]
        break
else:
    raise Exception("No suitable function found")

print("Win function address:", hex(function_address))

# could be confusing, but that second to last func is the one that prints Unauthorized
second_to_last_function_address = None
last_function_address = None
for function_info in reversed(response):
    if (
        function_info["name"].startswith("fcn.")
        and function_info["offset"] < function_address
    ):
        second_to_last_function_address = function_info["offset"]
        break
if second_to_last_function_address is None:
    raise Exception("No suitable function found before the last one")

data = {
    "command1": "s",  # seeking there
    "argument1": "0x{:x}".format(second_to_last_function_address),
    "command2": "pdfj",  # printing its disassembly
    "argument2": "",
}

response = requests.post(url, data=data)
response = response.text.split("Output:\n")[1].split("\n")[0]
response = loads(response)

to_replace_address = None
for op in response.get("ops"):
    if op["disasm"].startswith(
        "call sym.imp.puts"
    ):  # trying to find the call to puts that would print Unauthorized
        to_replace_address = op["offset"]
        break

if to_replace_address is None:
    raise Exception("No suitable instruction found")

print("Instruction to replace address:", hex(to_replace_address))

data = {
    "command1": "s",  # seeking there
    "argument1": "0x{:x}".format(to_replace_address),
    "command2": "wa",  # writing assembly
    "argument2": "call 0x{:x}".format(function_address),
}

response = requests.post(url, data=data).text

for line in response.split("\n"):
    if line.startswith("HCSC24{"):
        print("Flag:", line)
        break
else:
    raise Exception("No flag found")

import json

def write_json_tofile(response):
    data = json.loads(response.text)
    filename = "host_update.json"
    with open(filename, "w") as outfile:
        json.dump(data, outfile)
    return
#! /usr/bin/python

import json

def load_functions_from_file(functions, name):
    with open("../vita-headers/" + name + ".json") as file:
        data = json.load(file)
        libraries = data.values()
        for library in libraries:
            for module in library["modules"].values():
                functions.update(module["functions"])

functions = {}
load_functions_from_file(functions, "db")
load_functions_from_file(functions, "extra")

with open("nids.h", "w") as header:
    for name in sorted(functions):
        nid = functions[name]
        line = "NID(" + name + ", " + hex(nid) + ")\n"
        header.write(line)

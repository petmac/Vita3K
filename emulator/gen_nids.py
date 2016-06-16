#! /usr/bin/python

import json

with open("../vita-headers/db.json") as file:
    data = json.load(file)
    with open("nids.h", "w") as header:
        libraries = data.values()
        functions = {}
        for library in libraries:
            for module in library["modules"].values():
                functions.update(module["functions"])

        for name in sorted(functions):
            nid = functions[name]
            line = "NID(" + name + ", " + hex(nid) + ")\n"
            header.write(line)

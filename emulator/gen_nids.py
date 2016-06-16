#! /usr/bin/python

import json

with open("../vita-headers/db.json") as file:
    data = json.load(file)
    libraries = data.values()
    with open("nids.h", "w") as header:
        for library in libraries:
            for module in library["modules"].values():
                for function in module["functions"].items():
                    name = function[0]
                    nid = function[1]
                    line = "NID(" + name + ", " + hex(nid) + ")\n"
                    header.write(line)

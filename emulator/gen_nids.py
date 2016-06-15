#! /usr/bin/python

import json

with open("../vita-headers/db.json") as file:
    data = json.load(file)
    print(data)

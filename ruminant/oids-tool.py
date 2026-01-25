import sys
import os

# hack to import the oids module
sys.path.insert(0, os.path.dirname(__file__))
import oids  # noqa: E402


# recursively collect needed but undefined OIDs
# e.g. if the path is foo.bar.?.baz, it will add foo.bar.?
# and for foo.?.?.bar, it will add foo.? and foo.?.?
# and for foo.?, it will add foo.?
def append_unknowns(root, todo, base=[]):
    for key, value in root.items():
        if value["name"] == "?":
            todo.append(base + [key])

        append_unknowns(value["children"], todo, base + [key])


if len(sys.argv) > 1:
    # OIDs given as arguments, only process them
    todo = [[int(y) for y in x.split(".")] for x in sys.argv[1:]]
else:
    # no OIDs given as arguments, just process unknown ones
    todo = []
    append_unknowns(oids.OIDS, todo)


# recursively insert OID with name and create ? entries for unknown parts
# e.g. inserting foo.bar.baz will add foo.? if foo.bar is unknown
def insert(root, oid, name):
    if len(oid) == 1:
        if oid[0] not in root:
            root[oid[0]] = {"name": "?", "children": {}}

        root[oid[0]]["name"] = name
    else:
        if oid[0] not in root:
            root[oid[0]] = {"name": "?", "children": {}}

        insert(root[oid[0]]["children"], oid[1:], name)


# aks for each OID's name
try:
    for oid in todo:
        name = input(f"{'.'.join(str(x) for x in oid)}: ")

        if len(name.strip()) == 0:
            continue

        insert(oids.OIDS, oid, name)
except EOFError:
    pass


# sort them again and print them to the file
def walk(root, file, base):
    if root["name"] != "?":
        print(f"{'.'.join(str(x) for x in base)}: {root['name']}", file=file)

    for key in sorted(root["children"].keys()):
        walk(root["children"][key], file, base + [key])


# actually do the writing
with open(os.path.join(os.path.dirname(__file__), "oids.txt"), "w") as file:
    for key in sorted(oids.OIDS.keys()):
        walk(oids.OIDS[key], file, [key])

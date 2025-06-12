with open("./res", "r") as fd:
    lines = fd.readlines()
    fd.close()

fd = open("api", "w")
for line in lines:
    fd.write(line[44:])

fd.close()

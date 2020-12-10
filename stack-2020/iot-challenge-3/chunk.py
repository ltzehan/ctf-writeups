with open("out.txt") as ff:
    dump = ff.readlines()

data = []

i = 0
while i < len(dump):
    x = dump[i].split()
    if i % 3 == 0:
        data += x[13:17]
    elif i % 3 == 1:
        data += x[1:13]

    i += 1

# Truncate trailing ...
data = data[:-1]

with open("dude_my_chips", "wb") as ff:
    ff.write(bytearray([int(x, 16) for x in data]))

offsets = [
    0x1249, 0x12d5, 0x13d6, 0x13ed, 0x1479, 0x1505, 0x15a7, 0x16f7, 0x1799, 0x18e9, 0x198b, 0x1a42, 0x1ace, 0x1b75, 0x1c1c, 0x1cc3, 0x1d6a, 0x1e11, 0x1eb8, 0x1f5f, 0x2006, 0x20ad, 0x2154, 0x21fb, 0x22a2, 0x2349, 0x23f0, 0x2497, 0x253e, 0x25e5, 0x273f, 0x27e6, 0x288d
]

# Break before main so we can jump to the deobfuscating function
# Break again in puts to print the string
gdb.execute('''
    set print repeats 0
    b* 0x55555555772f
    b puts
''')

with open("out", "w") as ff:

    base = 0x555555554000
    for x in offsets:
        out = gdb.execute(f'''
            r
            set $rip={base+x}
            c
            x/s $rdi
        ''', to_string=True)

        out = out[out.find("\"")+1:-2]
        ff.write(f"{hex(x)}: {out}\n")

gdb.execute("quit")
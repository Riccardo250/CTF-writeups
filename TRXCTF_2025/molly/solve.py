# epic_gaming1
day = b"0n0_d@y_w3_w1ll_m33t                        "
res = b'\x00\x00\xb6\x00\x04\x01\xad\x01\x1c\x03\xa8\x02\xa4\x04\x13\x04\x18\x06\x0c\x06\xf0\x05\x3a\x0a\x78\x06\xf4\x09\x2c\x0a\x61\x08\x70\x0c\x2a\x09\xca\x08\xec\x10\x28\x0a\x3d\x0b\x4e\x07\x66\x0c\x30\x0c\x02\x08\x20\x08\xd2\x0f\x54\x0e\xf9\x0f\xf4\x0b\x0d\x0a\x80\x0d\x71\x0a\x24\x0f\xae\x10\x6c\x12\x90\x0b\x54\x10\x74\x10\x30\x11\x2d\x10\x48\x18\x1c\x0e'
res = [int.from_bytes(res[i: i + 2], "little") for i in range(0, len(res), 2)]
epic_gaming1 = b""
# any first char would do, since the result has to be 0
epic_gaming1 += b"A"
for i in range(1, len(day)):
    t = res[i] // i     
    epic_gaming1 += int.to_bytes((t - day[i]) % 256, 1, "little")

# epic_gaming2
local_28 =[0xde, 0xad ,0xbe, 0xef]
local_20 = [0xe8, 0x9d, 0x8e, 0x8b, 0xbc, 0xd4, 0x8d, 0]
epic_gaming2 = b""
for i in range(len(local_20) - 1):
    epic_gaming2 += int.to_bytes(local_20[i] ^ local_28[i % 4], 1 ,"little")

# epic_gaming3
epic_gaming3 = [0x3070, 0x336e, 0x3530, 0x7572, 0x6333]
epic_gaming3 = [int.to_bytes(i, 2, "big") for i in epic_gaming3]
epic_gaming3 = b"".join(epic_gaming3)

flag = f"TRX{{{epic_gaming2.decode()}_d3@r_{epic_gaming3.decode()}_{epic_gaming1.decode()}}}"
print(flag)
import struct

number = 28
number_bytes = number.to_bytes(1, byteorder = "big")

decoded_number = struct.unpack("!1b", number_bytes)
print("Origin Data:", number_bytes)
print("Decoded Data:", decoded_number[0])


number = 36
number_bytes = number.to_bytes(4, byteorder = "big")

decoded_number = struct.unpack("!i", number_bytes)
print("Origin Data:", number_bytes)
print("Decoded Data:", decoded_number[0])

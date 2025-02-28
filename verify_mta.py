# Hexadecimal strings
a_hex = "8187E101E8413652EF8965BE3A60C82924C98E77D9453572BBA3564B8BF7E54D"
b_hex = "245338869658D0CC100D35AFAC6E5FF49891BB5086F93876ADC2619ABC828CF2"
c_hex = "9BB2CA836A5451CDC8BE22EE4023041836179FD3AADB1368AF2D3799BA5B5464"
d_hex = "C23E61818458773EBB725AFD58F311E7717E0B122CCC58C66AAFF938507A68CC"

# Remove non-hex characters (e.g., G, H, I, etc.)
import re
a_hex = re.sub(r'[^0-9A-Fa-f]', '', a_hex)
b_hex = re.sub(r'[^0-9A-Fa-f]', '', b_hex)
c_hex = re.sub(r'[^0-9A-Fa-f]', '', c_hex)
d_hex = re.sub(r'[^0-9A-Fa-f]', '', d_hex)

# Convert hex strings to integers
a = int(a_hex, 16)
b = int(b_hex, 16)
c = int(c_hex, 16)
d = int(d_hex, 16)

# Define the modulus n (order of the secp256k1 curve)
# For secp256k1, n = 2^256 - 432420386565659656852420866394968145599
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Compute a * b mod n
product = (a * b) % n

# Compute c + d mod n
sum_cd = (c + d) % n

# Verify if a * b == c + d mod n
if product == sum_cd:
    print("Verification successful: a * b = c + d mod n")
else:
    print("Verification failed: a * b != c + d mod n")

# Print the values
print(f"a * b mod n: {hex(product)}")
print(f"c + d mod n: {hex(sum_cd)}")
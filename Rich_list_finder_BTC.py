import hashlib
import ecdsa
import base58

def generate_address(private_key):
    # Converting the private key from hexadecimal to bytes
    private_key_bytes = bytes.fromhex(private_key)

    # Generating the public key from the private key
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = bytes.fromhex("04") + verifying_key.to_string()

    # Hashing the public key using SHA-256 and RIPEMD-160
    hash_256 = hashlib.sha256(public_key).digest()
    hash_160 = hashlib.new("ripemd160", hash_256).digest()

    # Adding network byte (0x00 for Bitcoin mainnet)
    hash_160_with_network_byte = b"\x00" + hash_160

    # Getting the checksum
    checksum = hashlib.sha256(hashlib.sha256(hash_160_with_network_byte).digest()).digest()[:4]

    # Appending checksum to the hash_160_with_network_byte
    address_hex = hash_160_with_network_byte + checksum

    # Base58 encoding
    address = base58.b58encode(address_hex)

    #return address.decode("utf-8")
    return address.encode("utf-8")

def generate_key(user_input):
    # SHA-256 hash of the user input
    input_hash = hashlib.sha256(user_input.encode()).digest()

    # Converting the hash into an integer (mod q, where q is the order of the curve)
    key = int.from_bytes(input_hash, byteorder="big") % ecdsa.SECP256k1.order

    # Generating the corresponding private key
    private_key = ecdsa.SigningKey.from_secret_exponent(key, curve=ecdsa.SECP256k1)

    return private_key.to_string().hex()

# User input
user_input = input("Enter your input: ")

try:
    with open(r"C:\Users\KARAN SONAR\Downloads\Demo Software\Pyromid-mainx\Rich.txt", 'r') as file:
        addresses = file.readlines()
    
    for address in addresses:
        address = address.strip()
        private_key = generate_key(user_input)
        generated_address = generate_address(private_key)
        if generated_address == address:
            print("Private Key:", private_key)
            print("Generated Address:", generated_address)
            break
        elif():
            print(f"Generated Address: {generated_address}\nGenerated Private:{private_key}"),
        # elif():
            # print(f"Generated Private: {private_key}\nGenerated Public:{address})
    else:
        print(f"No matching address found in 'Rich.txt' Address: {generated_address}\n Generated Private:{private_key}")
except Exception as e:
    print("Error:",e)
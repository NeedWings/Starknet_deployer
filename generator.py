from loguru import logger
from utils import *
from SeedPhraseHelper.crypto import HDPrivateKey, HDKey
from config import *
client = GatewayClient(MAINNET)

def arrayify(hex_v):
    try:
        hex_v = hex(hex_v)
    except:
        pass
    try:
        if hex_v[1] == "x":
            hex_v = hex_v[2::]
    except:
        pass
    if len(hex_v) % 2 != 0:
        hex_v = "0" + hex_v
    if hex_v == "00":
        return [0]
    
    result = []

    for i in range(int(len(hex_v)/2)):
        offset = i*2
        result.append(int(hex_v[offset:offset+2], 16))
    
    return result

def concat(a, b):
    return a + b

def get_payload_hash(payload):
    m = hashlib.sha256()

    for value in payload:
        hex_value = hex(value)[2::]
        if len(hex_value) == 1:
            hex_value = "0"+ hex_value
        m.update(bytes.fromhex(hex_value))
    
    return m.hexdigest()



def hash_key_with_index(key, index):
    payload = concat(arrayify(key), arrayify(index))
    payload_hash = get_payload_hash(payload)
    return(int(payload_hash, 16))


def grid_key(key_seed):
    keyValueLimit = 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
    sha256EcMaxDigest = 0x10000000000000000000000000000000000000000000000000000000000000000

    maxAllowedVal = sha256EcMaxDigest - (sha256EcMaxDigest % keyValueLimit)

    i = 0

    key = 0

    while True:
        key = hash_key_with_index(key_seed, i)
        i+=1
        if key <= maxAllowedVal:
            break
    
    res = hex(abs(key % keyValueLimit))
    return res 

def get_argent_key_from_phrase(mnemonic):
    master_key = HDPrivateKey.master_key_from_mnemonic(mnemonic)
    
    root_keys = HDKey.from_path(master_key,"m/44'/60'/0'")
    acct_priv_key = root_keys[-1]

    keys = HDKey.from_path(acct_priv_key,'0/0')
    eth_key = hex(int(keys[-1]._key.to_hex(), 16))[2::]
    if len(eth_key) % 2 == 1:
        eth_key = "0"+eth_key
    master_key = HDPrivateKey.master_key_from_seed(eth_key)

    root_keys = HDKey.from_path(master_key,"m/44'/9004'/0'/0/0")


    private_key = grid_key(root_keys[-1]._key.to_hex())

    return private_key


def EIP2645Hashing(key0):
    N = 2**256

    starkCurveOrder = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F

    N_minus_n = N - (N % starkCurveOrder)

    i = 0
    while True:
        x = concat(arrayify(key0), arrayify(i))

        key = int(get_payload_hash(x), 16)

        if key < N_minus_n:
            return hex(key % starkCurveOrder)


def get_braavos_key_from_phrase(mnemonic):
    master_key = HDPrivateKey.master_key_from_mnemonic(mnemonic)

    root_keys = HDKey.from_path(master_key,"m/44'/9004'/0'/0/0")

    private_key = EIP2645Hashing(root_keys[-1]._key.to_hex())

    return private_key

def main():
    res = "seed phrase;private key\n"
    for i in range(amount_to_create):
        master_key, mnemonic = HDPrivateKey.master_key_from_entropy()
        
        if provider.lower() == "argent":
            private_key = get_argent_key_from_phrase(mnemonic)
        else:
            private_key = get_braavos_key_from_phrase(mnemonic) 
        res += f'{mnemonic};{private_key}\n'
    
    with open("wallets.csv", "w") as f:
        f.write(res)

   


if __name__ == "__main__":
    main()
    input("Soft successfully end work. Press Enter to quit")

from rabin import Rabin

rabin = Rabin(512)
rabin.generate_keys()

pbKey_Rabin, priKey_Rabin = rabin.get_public_key(), rabin.get_private_key()
cipherType = "" 
plaint = " "
encMessage = ""


def set_cipher_type(type):
    global cipherType
    cipherType = type
    print("Cipher is now :", cipherType)


def get_cipher_type():
    global cipherType
    return cipherType


def generateKey(string, key):
    key = list(key)
    if len(string) == len(key):
        return(key)
    else:
        for i in range(len(string) -
                       len(key)):
            key.append(key[i % len(key)])
    return("" . join(key))


def encryption(text, s, cipher=cipherType):
    plaintext = text
    global plaint
    global encMessage
    plaint = plaintext
    global cipherType
    cipherType = cipher

    print("encrypt func => Cipher is: ", cipherType)

    return rabin.encrypt(text)


# DECRYPTION OF HILL DOESNOT WORK :(


def decrypt(text, s, cipherType):
    global plaint
    print("decrypt func => Cipher is: ", cipherType)
    print(text)
    return rabin.decrypt(text)

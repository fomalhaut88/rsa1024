import ctypes


if __name__ == "__main__":
    Block = (ctypes.c_char * 128)

    modulo = Block()
    privatekey = Block()
    publickey = Block()

    message = Block()
    encrypted = Block()
    decrypted = Block()

    phrase = b"A secret message."
    message[:len(phrase)] = phrase

    dll = ctypes.CDLL(r'.\target\release\rsa1024.dll')

    dll.genkeys(modulo, privatekey, publickey)
    dll.encrypt(modulo, publickey, message, encrypted)
    dll.decrypt(modulo, privatekey, encrypted, decrypted)

    print(decrypted.value)

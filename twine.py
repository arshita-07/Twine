import random
import string
import binascii
from math import ceil
#import the functions to generate an 80/128 bit key schedule and to encrypt plain text
from algo import _key_schedule_80, _key_schedule_128, _encrypt


class Twine:
    key_space = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        #string.punctuation,
        #string.whitespace,
    ]

#This implementation supports 2 variants TWINE-80 and TWINE-128
    def __init__(self, key=None, key_size=0x80):
        if type(key_size) == str:
            key_size = int(key_size, 0)
        #If the key size is any value other than 80 or 128 raise an exception
        if key_size not in [0x50, 0x80]:
            raise ValueError(
                f"the given key bit length of: {key_size} is not supported"
            )

        #Code to generate an 80/128 bit key
        if not key:
            key = self.__generate_key(key_size)

        #the key generated is regarded as valid if its lenght is either 80 bits or 128 bits. If this condition fails, an exception is raised
        if self.__is_key_valid(key):
            self.key = key
        else:
            raise ValueError(f"The given key: {key} is not valid")

    @property
    def key_size(self):
        return len(str(self.key).encode("utf-8"))

    #Validated the key based on its key size 
    def __is_key_valid(self, key):
        kl = len(str(key).encode("utf-8"))
        if kl != 0x0A and kl != 0x10:
            return False
        return True

    #makes use of the random function to generate an 80/128 bit key (K) which will be used to generate a 32 bit round key
    def __generate_key(self, key_size):
        space = "".join(self.key_space)
        #for 80 bit key
        if key_size == 0x50:
            # The choice for random characters that can be chosen to form the key are specified at the top of this code withing the key_space variable
            return "".join(random.choice(space) for i in range(0x0A))
        #for 128 bit key
        elif key_size == 0x80:
            return "".join(random.choice(space) for i in range(0x10))

    # generates a 32 bit round key from the perviously generated 80/128 bit keys
    def __generate_RK(self):
        # for 80 bit key
        if self.key_size == 0x50:
            return _key_schedule_80(int(self.key.encode("utf-8").hex(), 16))
        # for 128 bit key
        else:
            return _key_schedule_128(int(self.key.encode("utf-8").hex(), 16))

    #blocks corresponds to plain text
    def __iterblocks(self, blocks):
        #calc the length of the blocks parameter and calculate how many block of length 16 can be created
        for i in range(ceil(len(blocks) / 16)):
            #since we have used ceil, incase the lenght of blocks isnt an exact multiple of 16 we will have extra bits remaining at the end so return that
            if i * 16 + 16 > len(blocks):
                yield blocks[i * 16 : len(blocks)]
            #return 16 bits from the block till the index falls within the range of block length
            else:
                yield blocks[i * 16 : i * 16 + 16]

    # function to perform encryption 
    def encrypt(self, plaintext):
        _c = ""
        plaintext = plaintext.encode("utf-8").hex()
        #generate round key
        RK = self.__generate_RK()
        #form sub-blocks from the plain text
        for block in self.__iterblocks(plaintext):
            #call encrypt function and append the output to _c
            cblock = hex(_encrypt(int(block, 16), RK))[2:]
            _c += cblock
        return _c

# showing implementation for 128 bit key
twine = Twine(key_size=0x80)

#Take user input 
txt = input("Enter plain text that is to be encrypted\n");

print()
print('plaintext : ', txt)
ciphertext = twine.encrypt(txt)
print()
print('cipher text : ', ciphertext)


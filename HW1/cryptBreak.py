"""
Homework Number: 1
Name: Tycho Halpern
ECN Login: thalper
Due Date: 1/20/2022
"""

# I used DecryptForFun.py as a base for this function, and modified it to fit the needs of the assignment

from BitVector import *

def cryptBreak(ciphertextFile, key_bv):
    # Arguments:
    # * ciphertextFile: String containing file name of the ciphertext
    # * key_bv: 16-bit BitVector for the decryption key
    #
    # Function Description:
    # Attempts to decrypt the ciphertext within ciphertextFile file using key_bv and returns the original plaintext as a string
    PassPhrase = "Hopes and dreams of a million years"                          #(C)

    BLOCKSIZE = 16                                                              #(D)
    numbytes = BLOCKSIZE // 8                                                   #(E)

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                  #(F)
    for i in range(0,len(PassPhrase) // numbytes):                              #(G)
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                         #(H)
        bv_iv ^= BitVector( textstring = textstr )     

    with open(ciphertextFile) as FILEIN:
        encrypted_bv = BitVector( hexstring = FILEIN.read() )

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )                                    #(T)

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv                                            #(U)
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):                          #(V)
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]                          #(W)
        temp = bv.deep_copy()                                                   #(X)
        bv ^=  previous_decrypted_block                                         #(Y)
        previous_decrypted_block = temp                                         #(Z)
        bv ^=  key_bv                                                           #(a)
        msg_decrypted_bv += bv                                                  #(b)

    # Extract plaintext from the decrypted bitvector:    
    return msg_decrypted_bv.get_text_from_bitvector()                           #(c)

if __name__ == "__main__":
    for integer in range(2**16):
        key_bv = BitVector(intVal=integer, size=16)
        decryptedMessage = cryptBreak("ciphertext.txt", key_bv)
        if "Douglas Adams" in decryptedMessage:
            print("Encryption key: ", integer)
            print("Message: ", decryptedMessage)
            break


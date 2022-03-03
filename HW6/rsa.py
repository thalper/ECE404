#Homework Number: hw06
#Name: Tycho Halpern
#ECN login: thalper
#Due Date: March 3, 2022
#!/usr/bin/env python3

from email import message_from_binary_file
import PrimeGenerator
import sys
from BitVector import *


e = 65537

def GCD(a,b):
    while b:
        a,b = b, a%b
    return a

def MI(num, mod):
    '''
    This function uses ordinary integer arithmetic implementation of the
    Extended Euclid's Algorithm to find the MI of the first-arg integer
    vis-a-vis the second-arg integer.
    '''
    NUM = num; MOD = mod
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        q = num // mod
        num, mod = mod, num % mod
        x, x_old = x_old - q * x, x
        y, y_old = y_old - q * y, y
    if num != 1:
        print("\nNO MI. However, the GCD of %d and %d is %u\n" % (NUM, MOD, num))
    else:
        MI = (x_old + MOD) % MOD
        return MI

def encrypt(messageFileStr, pFileStr, qFileStr, encryptedFileStr):
    encryptedFile = open(encryptedFileStr, 'w')
    with open(pFileStr) as pFile:
        p = int(next(pFile))
    with open(qFileStr) as qFile:
        q = int(next(qFile))
    n = p*q
    d = MI(e, (p-1)*(q-1))
    message_bv = BitVector(filename=messageFileStr)
    while (message_bv.more_to_read):
        curr = message_bv.read_bits_from_file(128)
        if len(curr) < 128:
            curr.pad_from_right(128-len(curr))
        curr.pad_from_left(128)
        # print(curr.get_bitvector_in_hex())
        output = pow(curr.int_val(),e,n)
        output_bv = BitVector(intVal = output, size=256)
        # print(output_bv.get_bitvector_in_hex())
        #output_bv.write_to_file(encryptedFile)
        encryptedFile.write(output_bv.get_bitvector_in_hex())
    encryptedFile.close()
    

def decrypt(encryptedFileStr, pFileStr, qFileStr, decryptedFileStr):
    decryptedFile = open(decryptedFileStr, 'w')
    with open(pFileStr) as pFile:
        p = int(next(pFile))
    with open(qFileStr) as qFile:
        q = int(next(qFile))
    n = p*q
    d = MI(e, (p-1)*(q-1))
    cipher_bv = BitVector(filename=encryptedFileStr)
    while (cipher_bv.more_to_read):
        temp = cipher_bv.read_bits_from_file(512)
        curr = BitVector(hexstring = temp.get_bitvector_in_ascii())
        # print(curr.get_bitvector_in_hex())
        p_crt = pow(curr.int_val(), d, p)
        q_crt = pow(curr.int_val(), d, q)
        output = BitVector(intVal= (((p_crt * q * MI(q, p)) + (q_crt * p * MI(p,q))) % n), size = 256)
        # print(output.get_bitvector_in_hex())
        out_bv = BitVector(intVal = output.int_val(), size = 128)
        decryptedFile.write(out_bv.get_text_from_bitvector())
    decryptedFile.close()


def setPQ(pFile, qFile):
    generator = PrimeGenerator.PrimeGenerator( bits = 128 )
    while (True):
        p = generator.findPrime()
        if ((p>>126) == 3 and GCD(p-1,e) == 1):
            q = generator.findPrime()
            if ((q>>126) == 3 and p != q and GCD(q-1,e) == 1):
                break
    with open(pFile, "w") as pTxt:
        pTxt.write(str(p))
    with open(qFile, "w") as qTxt:
        qTxt.write(str(q))


if __name__ == "__main__":
    if sys.argv[1] == '-g' and len(sys.argv) == 4:
        setPQ(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == '-e' and len(sys.argv) == 6:
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif sys.argv[1] == '-d' and len(sys.argv) == 6:
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        print("Incorrect input format")
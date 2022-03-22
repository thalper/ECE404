#Homework Number: hw04
#Name: Tycho Halpern
#ECN login: thalper
#Due Date: February 10, 2022
#!/usr/bin/env python3

from operator import inv
import os
import sys

from BitVector import *

mod = BitVector(bitstring='100011011')

def genTables(subTable, invSubTable):
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(mod, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(mod, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubTable.append(int(b))

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(mod, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), mod, 8)
    return newword, round_constant

def xor(statearray, keys, i):
    out = statearray
    subKey = [0] * 16

    [j, k] = keys[i].divide_into_two()
    [subKey[0], subKey[1]] = j.divide_into_two()
    [subKey[2], subKey[3]] = k.divide_into_two()

    [j, k] = keys[i + 1].divide_into_two()
    [subKey[4], subKey[5]] = j.divide_into_two()
    [subKey[6], subKey[7]] = k.divide_into_two()

    [j, k] = keys[i + 2].divide_into_two()
    [subKey[8], subKey[9]] = j.divide_into_two()
    [subKey[10], subKey[11]] = k.divide_into_two()

    [j, k] = keys[i + 3].divide_into_two()
    [subKey[12], subKey[13]] = j.divide_into_two()
    [subKey[14], subKey[15]] = k.divide_into_two()

    for x in range(16):
        out[x % 4][x // 4] = out[x % 4][x // 4]^subKey[x]

    return out

def MixCol(statearray):
    out = [[BitVector(intVal=0, size=8) for x in range(4)] for x in range(4)]

    constantTwo = BitVector(intVal=2, size=8)
    constantThree = BitVector(intVal=3, size=8)

    for x in range(4):
        col1 = constantTwo.gf_multiply_modular(statearray[0][x], mod, 8)
        col2 = constantThree.gf_multiply_modular(statearray[1][x], mod, 8)
        col3 = col1^col2
        col3 = col3^statearray[2][x]
        col3 = col3^statearray[3][x]
        out[0][x] = col3
    for x in range(4):
        col1 = constantTwo.gf_multiply_modular(statearray[1][x], mod, 8)
        col2 = constantThree.gf_multiply_modular(statearray[2][x], mod, 8)
        col3 = col1^col2
        col3 = col3^statearray[0][x]
        col3 = col3^statearray[3][x]
        out[1][x] = col3
    for x in range(4):
        col1 = constantTwo.gf_multiply_modular(statearray[2][x], mod, 8)
        col2 = constantThree.gf_multiply_modular(statearray[3][x], mod, 8)
        col3 = col1^col2
        col3 = col3^statearray[0][x]
        col3 = col3^statearray[1][x]
        out[2][x] = col3
    for x in range(4):
        col1 = constantTwo.gf_multiply_modular(statearray[3][x], mod, 8)
        col2 = constantThree.gf_multiply_modular(statearray[0][x], mod, 8)
        col3 = col1^col2
        col3 = col3^statearray[1][x]
        col3 = col3^statearray[2][x]
        out[3][x] = col3
    return out



def invMixCol(statearray):
    out = [[BitVector(intVal=0, size=8) for x in range(4)] for x in range(4)]

    constantE = BitVector(intVal=14, size=8)
    constantB = BitVector(intVal=11, size=8)
    constantD = BitVector(intVal=13, size=8)
    constant9 = BitVector(intVal=9, size=8)

    for x in range(4):
        col1 = constantE.gf_multiply_modular(statearray[0][x], mod, 8)
        col2 = constantB.gf_multiply_modular(statearray[1][x], mod, 8)
        col3 = constantD.gf_multiply_modular(statearray[2][x], mod, 8)
        col4 = constant9.gf_multiply_modular(statearray[3][x], mod, 8)
        col1 ^= col2
        col3 ^= col4

        out[0][x] = col1.__xor__(col3)
    for x in range(4):
        col1 = constantE.gf_multiply_modular(statearray[1][x], mod, 8)
        col2 = constantB.gf_multiply_modular(statearray[2][x], mod, 8)
        col3 = constantD.gf_multiply_modular(statearray[3][x], mod, 8)
        col4 = constant9.gf_multiply_modular(statearray[0][x], mod, 8)
        col1 ^= col2
        col3 ^= col4

        out[1][x] = col1.__xor__(col3)
    for x in range(4):
        col1 = constantE.gf_multiply_modular(statearray[2][x], mod, 8)
        col2 = constantB.gf_multiply_modular(statearray[3][x], mod, 8)
        col3 = constantD.gf_multiply_modular(statearray[0][x], mod, 8)
        col4 = constant9.gf_multiply_modular(statearray[1][x], mod, 8)
        col1 ^= col2
        col3 ^= col4

        out[2][x] = col1.__xor__(col3)
    for x in range(4):
        col1 = constantE.gf_multiply_modular(statearray[3][x], mod, 8)
        col2 = constantB.gf_multiply_modular(statearray[0][x], mod, 8)
        col3 = constantD.gf_multiply_modular(statearray[1][x], mod, 8)
        col4 = constant9.gf_multiply_modular(statearray[2][x], mod, 8)
        col1 ^= col2
        col3 ^= col4

        out[3][x] = col1^col3
    return out


def shiftRows(statearray):
    temp = [0] * 16
    out = [[0 for i in range(4)] for i in range(4)]

    for i in range(16):
        temp[i] = statearray[i % 4][i // 4]

    out[0][0] = temp[0]
    out[0][1] = temp[4]
    out[0][2] = temp[8]
    out[0][3] = temp[12]
    out[1][0] = temp[5]
    out[1][1] = temp[9]
    out[1][2] = temp[13]
    out[1][3] = temp[1]
    out[2][0] = temp[10]
    out[2][1] = temp[14]
    out[2][2] = temp[2]
    out[2][3] = temp[6]
    out[3][0] = temp[15]
    out[3][1] = temp[3]
    out[3][2] = temp[7]
    out[3][3] = temp[11]

    return out

def invShiftRows(statearray):
    temp = [0] * 16
    out = [[0 for i in range(4)] for i in range(4)]

    for i in range(16):
        temp[i] = statearray[i % 4][i // 4]

    out[0][0] = temp[0]
    out[0][1] = temp[4]
    out[0][2] = temp[8]
    out[0][3] = temp[12]
    out[1][0] = temp[13]
    out[1][1] = temp[1]
    out[1][2] = temp[5]
    out[1][3] = temp[9]
    out[2][0] = temp[10]
    out[2][1] = temp[14]
    out[2][2] = temp[2]
    out[2][3] = temp[6]
    out[3][0] = temp[7]
    out[3][1] = temp[11]
    out[3][2] = temp[15]
    out[3][3] = temp[3]

    return out

def substitute(statearray, subTable):
    out = statearray
    for x in range(4):
        for y in range(4):
            [row, col] = out[y][x].divide_into_two()
            row.pad_from_left(4)
            col.pad_from_left(4)
            row = row.int_val()
            col = col.int_val()
            out[y][x] = BitVector(intVal=subTable[row*16 + col], size=8)
    return out

def invSubstitute(statearray, invSubTable):
    out = statearray
    for x in range(4):
        for y in range(4):
            [row, col] = out[y][x].divide_into_two()
            row.pad_from_left(4)
            col.pad_from_left(4)
            row = row.int_val()
            col = col.int_val()
            out[y][x] = BitVector(intVal=invSubTable[row * 16 + col], size=8)
    return out


def encrypt(inFileStr, keyFileStr, encryptedFileStr):
    subTable = []
    invSubTable = []
    genTables(subTable, invSubTable)

    keyFile = open(keyFileStr)
    key_bv = BitVector(textstring=keyFile.read(32))
    keyFile.close()

    key_words = gen_key_schedule_256(key_bv)
    bv = BitVector(filename=inFileStr)
    encryptedFile = open(encryptedFileStr, 'w')
    statearray = [[0 for x in range(4)] for x in range(4)]

    while (bv.more_to_read):
        for x in range(4):
            for y in range(4):
                curr = bv.read_bits_from_file(8)
                statearray[y][x] = curr
        statearray = xor(statearray, key_words, 0)
        for round in range(1, 14):
            statearray = substitute(statearray, subTable)
            statearray = shiftRows(statearray)
            statearray = MixCol(statearray)
            statearray = xor(statearray, key_words, (round*4))
        statearray = substitute(statearray, subTable)
        statearray = shiftRows(statearray)
        statearray = xor(statearray, key_words, (14 * 4))

        for x in range(4):
            for y in range(4):
                encryptedFile.write(statearray[y][x].get_bitvector_in_hex().rstrip())
    encryptedFile.close()
    return



def decrypt(encryptedFileStr, keyFileStr, decryptedFileStr):
    subTable = []
    invSubTable = []
    genTables(subTable, invSubTable)
    keyFile = open(keyFileStr)
    key_bv = BitVector(textstring=keyFile.read(32))
    keyFile.close()
    key_words = gen_key_schedule_256(key_bv)
    encryptedFile = open(encryptedFileStr, 'r')
    bv = BitVector(hexstring=encryptedFile.read())
    decryptedFile = open(decryptedFileStr, 'w')
    statearray = [[0 for i in range(4)] for i in range(4)]

    for i in range(0, len(bv) // 128):
        work = bv[i*128:(i+1) *128]
        for i in range(16):
            statearray[i%4][i//4] = work[i*8:(i+1)*8]
        statearray = xor(statearray, key_words, (14 * 4))
        for round in range(1,14):
            statearray = invShiftRows(statearray)
            statearray = invSubstitute(statearray, invSubTable)
            statearray = xor(statearray, key_words, (14-round)*4)
            statearray = invMixCol(statearray)
        statearray = invShiftRows(statearray)
        statearray = invSubstitute(statearray, invSubTable)
        statearray = xor(statearray, key_words, 0)
        for i in range(4):
            for j in range(4):
                decryptedFile.write(statearray[j][i].get_bitvector_in_ascii().rstrip("\0"))
    decryptedFile.close()
    return

if __name__ == '__main__':
    if sys.argv[1] == '-e' and len(sys.argv) == 5:
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == '-d' and len(sys.argv) == 5:
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print("Incorrect input format")
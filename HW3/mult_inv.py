#!/usr/bin/env python

##  mult_inv.py

import sys
if len(sys.argv) != 3:
    sys.exit("\nUsage:   %s  <integer>  <integer>\n" % sys.argv[0])

a,b = int(sys.argv[1]),int(sys.argv[2])

def bgcd(a,b):
    if a == b: return a                                         #(A)
    if a == 0: return b                                         #(B)
    if b == 0: return a                                         #(C)
    if (~a & 1):                                                #(D)
        if (b &1):                                              #(E)
            return bgcd(a >> 1, b)                              #(F)
        else:                                                   #(G)
            return bgcd(a >> 1, b >> 1) << 1                    #(H)
    if (~b & 1):                                                #(I)
        return bgcd(a, b >> 1)                                  #(J)
    if (a > b):                                                 #(K)
        return bgcd( (a-b) >> 1, b)                             #(L)
    return bgcd( (b-a) >> 1, a )                                #(M)

def bDivide(a,b):
    if b == 1:
        return [a,0]
    if a == 0:
        return [0,b]
    negative = False
    if a < 0:
        a = -a
        if b > 0:
            negative = True
        else:
            b = -b
    elif b < 0:
        negative = True
        b = -b
    count = 0
    while a > b:
        a -= b
        count += 1
    if negative:
        count = -count
        a = b - a
    return [count, a]

def bMult(a,b):
    negative = False
    if a == 0 or b == 0:
        return 0
    if a < 0:
        a = -a
        if b > 0:
            negative = True
        else:
            b = -b
    elif b < 0:
        negative = True
        b = -b
    val = 0
    i = 0
    while b:
        if (b&1):
            val += a<<i
        b = b>>1
        i+=1
    return -val if negative else val

def bMI(a,b):
    mod = b
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        temp = bDivide(a,mod)
        q = temp[0]
        a = mod
        mod = temp[1]
        x, x_old = x_old - bMult(q,x), x
        y, y_old = y_old - bMult(q,y), y
    return bDivide(x_old + b, b)[1]
        


gcdval = bgcd(a, b)
if gcdval != 1:
    print("\nNO MI. However, the GCD of %d and %d is %u\n" % (a, b, gcdval))
else:
    print("\nMI of %d modulo %d is: %d\n" % (a, b, bMI(a,b)))


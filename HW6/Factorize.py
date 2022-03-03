#!/usr/bin/env python

##  Factorize.py
##  Author: Avi Kak
##  Date: February 26, 2011 
##  Modified: Febrary 25, 2012

##  Uncomment line (F9) and comment out line (F10) if you want to see the results
##  with the simpler form of the Pollard-Rho algorithm.

import random
import sys

def factorize(n):                                                            #(F1)
    prime_factors = []                                                       #(F2)
    factors = [n]                                                            #(F3)
    while len(factors) != 0:                                                 #(F4)
        p = factors.pop()                                                    #(F5)
        if test_integer_for_prime(p):                                        #(F6)
            prime_factors.append(p)                                          #(F7)
            continue                                                         #(F8)
#        d = pollard_rho_simple(p)                                           #(F9)
        d = pollard_rho_strong(p)                                            #(F10)
        if d == p:                                                           #(F11)
            factors.append(d)                                                #(F12)
        else:                                                                #(F13)
            factors.append(d)                                                #(F14)
            factors.append(p//d)                                             #(F15)
    return prime_factors                                                     #(F16)

def test_integer_for_prime(p):                                               #(P1)
    probes = [2,3,5,7,11,13,17]                                              #(P2)
    for a in probes:                                                         #(P3)
        if a == p: return 1                                                  #(P4)
    if any([p % a == 0 for a in probes]): return 0                           #(P5)
    k, q = 0, p-1                                                            #(P6)
    while not q&1:                                                           #(P7)
        q >>= 1                                                              #(P8)
        k += 1                                                               #(P9)
    for a in probes:                                                         #(P10)
        a_raised_to_q = pow(a, q, p)                                         #(P11)
        if a_raised_to_q == 1 or a_raised_to_q == p-1: continue              #(P12)
        a_raised_to_jq = a_raised_to_q                                       #(P13)
        primeflag = 0                                                        #(P14)
        for j in range(k-1):                                                 #(P15)
            a_raised_to_jq = pow(a_raised_to_jq, 2, p)                       #(P16)
            if a_raised_to_jq == p-1:                                        #(P17)
                primeflag = 1                                                #(P18)
                break                                                        #(P19)
        if not primeflag: return 0                                           #(P20)
    probability_of_prime = 1 - 1.0/(4 ** len(probes))                        #(P21)
    return probability_of_prime                                              #(P22)

def pollard_rho_simple(p):                                                   #(Q1)
    probes = [2,3,5,7,11,13,17]                                              #(Q2)
    for a in probes:                                                         #(Q3)
        if p%a == 0: return a                                                #(Q4)
    d = 1                                                                    #(Q5)
    a = random.randint(2,p)                                                  #(Q6)
    random_num = []                                                          #(Q7)
    random_num.append( a )                                                   #(Q8)
    while d==1:                                                              #(Q9)
        b = random.randint(2,p)                                              #(Q10)
        for a in random_num[:]:                                              #(Q11)
            d = gcd( a-b, p )                                                #(Q12)
            if d > 1: break                                                  #(Q13)
        random_num.append(b)                                                 #(Q14)
    return d                                                                 #(Q15)

def pollard_rho_strong(p):                                                   #(R1)
    probes = [2,3,5,7,11,13,17]                                              #(R2)
    for a in probes:                                                         #(R3)
        if p%a == 0: return a                                                #(R4)
    d = 1                                                                    #(R5)
    a = random.randint(2,p)                                                  #(R6)
    c = random.randint(2,p)                                                  #(R7)
    b = a                                                                    #(R8)
    while d==1:                                                              #(R9)
        a = (a * a + c) % p                                                  #(R10)
        b = (b * b + c) % p                                                  #(R11)
        b = (b * b + c) % p                                                  #(R12)
        d = gcd( a-b, p)                                                     #(R13)
        if d > 1: break                                                      #(R14)
    return d                                                                 #(R15)

def gcd(a,b):                                                                #(S1)
    while b:                                                                 #(S2)
        a, b = b, a%b                                                        #(S3)
    return a                                                                 #(D4)

if __name__ == '__main__':                                                   #(A1)

    if len( sys.argv ) != 2:                                                 #(A2)
        sys.exit( "Call syntax:  Factorize.py  number" )                     #(A3)
    p = int( sys.argv[1] )                                                   #(A4)
    factors = factorize(p)                                                   #(A5)
    print("\nFactors of %d:" % p)                                            #(A6)
    for num in sorted(set(factors)):                                         #(A7)
        print("%s %d ^ %d" % ("    ", num, factors.count(num)))              #(A8)

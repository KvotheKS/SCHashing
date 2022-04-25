import numpy as np
import random
import math

def MillerRabin(n, certainty=15):
    if n%2 == 0:
        return False
    # Determinar r e d, iterando de 2^1 a 2^x tal que 2^x<=n
    i = 2 
    cr = -1
    neg = n-1
    print(1)
    while i <= neg:
        if neg%i == 0:
            cr = i
        i*=2
    r = int(math.log(cr,2))
    d = int(neg/cr)
    print(2)
    # rodar certainty vezes, tal que a chance de um falso positivo
    # é 4^-certainty
    for _ in range(certainty):
        # gera um numero no intervalo [2,n-1)
        a = random.randrange(2,n-1)
        print(3)
        #Teorema de Fermat
        x = (a**d)%n
        if x == 1 or x == n-1:
            continue

        flag = False

        for _ in range(r-1):
            print(4)
            x = (x**2)%n
            if x == n-1:
                flag = True
                break

        if flag:
            continue

        return False

    return True

def genPrime(choice = -1, size=1024):
    prm = 0
    while(True):
        prm = random.getrandbits(size)
        if MillerRabin(prm) and prm != choice:
            break
    return prm

def main():
    return
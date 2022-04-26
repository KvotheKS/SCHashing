import random
import math

def MillerRabin(n, certainty=1):
    if n%2 == 0:
        return False
    # Determinar r e d, iterando de 2^1 a 2^x tal que 2^x<=n
    i = 2 
    cr = -1
    neg = n-1
    #print(1)
    while i <= neg:
        if neg%i == 0:
            cr = i
        i*=2
    r = int(math.log(cr,2))
    d = int(neg//cr)
    #print(r,d)
    # rodar certainty vezes, tal que a chance de um falso positivo
    # é 4^-certainty
    for _ in range(certainty):
        # gera um numero no intervalo [2,n-1)
        a = random.randrange(2,n-1)
        #print(3)
        #Teorema de Fermat
        x = pow(a,d,n)
        #print('mod')
        if x == 1 or x == n-1:
            continue
        #print('r')
        flag = False

        for _ in range(r-1):
        #    print(4)
            x = pow(x,2,n)
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
        #print(prm, end='\n\n\n\n\n')
        if MillerRabin(prm) and prm != choice:
            break
    return prm

#retorna Pk,Sk
def RSAKeys():
    #gera primos P e Q, tal que P != Q
    p = genPrime()
    q = genPrime(p)
    # computar n e phi(n) 
    n,phin = p*q,(p-1)*(q-1)
    
    # computar "e" tal que ele nao tem divisores em comum com phi(n)
    e = 3
    while math.gcd(e,phin) > 1:
        e += 2
    
    # inverso multiplicativo modular de "e"
    d = pow(e,-1,phin)
    return (e,n), (d,n)

def RSACypher(message, pk):
    # transforma a string unicode em um array de bits utf-8
    out = int.from_bytes(message.encode('latin1'), byteorder='big')
    out = int(pow(out, pk[0], pk[1]))
    out = out.to_bytes(max(1,math.ceil(out.bit_length()/8)), byteorder='big')
    return out.decode('latin1')

def RSADecypher(cypher, sk):
    out = int.from_bytes(cypher.encode('latin1'), byteorder='big')
    out = int(pow(out, sk[0], sk[1]))
    out = out.to_bytes(max(1,math.ceil(out.bit_length()/8)), byteorder='big')
    return out.decode('latin1')

def RSA(message):
    pk, sk = RSAKeys()
    cipher = RSACypher(message,pk)
    print(cipher)
    print(RSADecypher(cipher, sk))

RSA('Testes Bons Belos Bonitos :^)')
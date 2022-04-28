import random
import math
import hashlib
from base64 import b64encode, b64decode

def MillerRabin(n, certainty=15):
    """
        A função recebe 2 parâmetros:
            n -> número que queremos testar a primalidade
            certainty -> grau de certeza do teste de primalidade. Quanto maior certainty, maior 
            a precisão do teste tal que a chance de um falso positivo seja de 4^(-certainty)
        
        Retorna:
            True -> Se n é provavelmente primo
            False -> Se n com certeza não é primo 
    """
    
    if n % 2 == 0: # Caso o número seja par, obviamente não é primo
        return False

    # Transformar n-1 em d * 2^r, com d sendo ímpar e r > 0. Os parâmetros r e d serão determinados
    # a partir da fatoração de potências de 2^i que vão de 2^1 a 2^x de forma tal que 2^x <= n-1.
    i = 2 
    pow2r = -1
    n1 = n-1
    while i <= n1:
        if n1 % i == 0:
            pow2r = i
        i *= 2
    r = int(math.log(pow2r, 2))  # r = log(pow2r) = log(2^r)
    d = int(n1 // pow2r)         # d = (n - 1) / (2^r)

    # Executamos o teste de primalidade certainty vezes até determinar que n é um provável primo
    for _ in range(certainty):
        # Gera um número a (base) no intervalo [2,n-1)
        a = random.randrange(2, n1)

        # Condições do teste de Miller-Rabin:
        #   1) a^d ≡ 1 (mod n)                  --> a^d - 1 = n * h, para algum h inteiro
        #   2) a^(d * 2^r') ≡ -1 (mod n)        --> a^(d * 2^r') + 1 = n * h, para algum h inteiro e 0 <= r'< r
        #
        #   Note que: a^(d * 2^r') ≡ -1 (mod n) == a^(d * 2^r') ≡ (n-1) (mod n)

        x = pow(a, d, n)      # x = a^d (mod n)
        if x == 1 or x == n1: # Primeira condição e Segunda condição quando r' = 0
            continue

        flag = False # Booleano para decidir se passa para a próxima iteração

        for _ in range(r-1): # Itera r' por 1 até r-1
            x = pow(x, 2, n) # x = a^(d * 2^r')

            if x == n1: # Segunda condição para quando r' > 0 e r' < r
                flag = True # Indica que o loop passa para a próxima iteração
                break

        if flag: # Se flag for False, n com certeza não é primo
            continue

        return False

    return True

def genPrime(choice = -1, size=1024):
    """
        A função recebe 2 parâmetros opcionais:
            choice -> Número primo que eu não quero pegar
            size -> Tamanho em bits do número primo que quero gerar
        Retorno:
            prime -> número primo diferente de choice com size bits
    """
    prime = 1

    # Roda até achar um primo de size bits
    while(True):
        # Gera um número randômico de size bits
        prime = random.getrandbits(size)

        # Verifica se esse número é provalvemente um primo e diferente de choice
        if MillerRabin(prime) and prime != choice:
            break
    return prime

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

def OAEP(message):
    X,Y = OAEPCypher(message)
    OAEPout = OAEPDecypher(X,Y)

    print(X,Y)
    print(OAEPout)
"""
    Tanto a i2osp quanto a mgf1 retorna um objeto da classe bytes.
"""
def i2osp(integer, size = 4):
    return b"".join([chr((integer >> (8 * i)) & 0xFF).encode() for i in reversed(range(size))])

def mgf1(input_str, length):
    """Mask generation function."""
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hashlib.sha3_256(input_str + C).digest()
        counter += 1
    return output[:length]

# tuple, bytes, str -> bytes
def OAEPCypher(message, label="", k = 256):
    lHash = hashlib.sha3_256(label.encode('latin1')).digest()

    padding = ('0'*(k-len(message)-2*len(lHash)-2)).encode('latin1')
    
    db = lHash + padding + int(0x01).to_bytes(1,byteorder='big') + message
    
    r = int(random.getrandbits(len(lHash)*8)).to_bytes(len(lHash), byteorder='big')
    
    dbmask = mgf1(r, k-len(lHash)-1)

    maskedb = int.from_bytes(db,byteorder='big') ^ int.from_bytes(dbmask, byteorder='big')
    maskedbits = maskedb.to_bytes(k-len(lHash)-1, byteorder='big')
    seedMask = mgf1(maskedbits, len(lHash))
    maskedseed = (int.from_bytes(r, byteorder='big') ^ int.from_bytes(seedMask, byteorder='big')).to_bytes(len(lHash), byteorder='big')
    return int(0x00).to_bytes(1, byteorder='big') + maskedseed + maskedbits

# bytes, str -> bytes
def OAEPDecypher(EM, label="", k = 256):
    lHash = hashlib.sha3_256(label.encode('latin1')).digest()
    maskedseed = EM[1:len(lHash)+1]
    maskedb = EM[len(lHash) + 1:]
    seedMask = mgf1(maskedb , len(lHash))
    seed = int.from_bytes(maskedseed, byteorder='big') ^ int.from_bytes(seedMask, byteorder='big')
    seedbits = seed.to_bytes(max(1,math.ceil(seed.bit_length()/8)), byteorder='big')

    dbmask = mgf1(seedbits, k - len(lHash) -1)

    db = int.from_bytes(maskedb, byteorder='big') ^ int.from_bytes(dbmask, byteorder='big')
    dbits = db.to_bytes(max(1,math.ceil(db.bit_length()/8)), byteorder='big')

    lHashl = dbits[:len(lHash)]

    i = len(lHash)
    while(i < len(dbits) and dbits[i] == 48):
        i+=1
    
    if i == len(dbits) or lHash != lHashl:
        print("Decryption error OEAP")
        return
    
    message = dbits[i+1:]
    
    return message

l = OAEPCypher('Téâãstes Bons Belos Bonitos :^)'.encode('latin1'))
#print(l)
r = OAEPDecypher(l).decode('latin1')
print(r)
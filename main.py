import random
import math
import hashlib
import secrets 
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

def RSAKeys():
    """
        _ -> (e,n), (d,n)

        Computamos tanto PK quanto SK, seguindo o teste de primalidade MillerRabin.
        Os valores de P e Q são de 1024 bits cada, ou seja, o tamanho do modulo n
        é de 2048!
    """
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
    """
        bytes, (e,n) -> bytes
    """
    # transforma a string unicode em um array de bits utf-8
    out = int.from_bytes(message, byteorder='big')
    out = int(pow(out, pk[0], pk[1]))
    out = out.to_bytes(max(1,math.ceil(out.bit_length()/8)), byteorder='big')
    return out

def RSADecypher(cypher, sk):
    """
        bytes, (d,n) -> bytes
    """
    out = int.from_bytes(cypher, byteorder='big')
    out = int(pow(out, sk[0], sk[1]))
    out = out.to_bytes(max(1,math.ceil(out.bit_length()/8)), byteorder='big')
    return out


# def RSA(message):
#     pk, sk = RSAKeys()
#     cipher = RSACypher(message,pk)
#     print(cipher)
#     print(RSADecypher(cipher, sk))

def i2osp(integer, size = 4):
    """
        int, size -> bytes 

        Segue os padrões do RFC. É utilizado tanto no mgf1 quanto no processo
        de cifração e decifração do RSA.
        Vale notar que o tamanho do objeto bytes vai ser igual ao size.
    """
    return b"".join([chr((integer >> (8 * i)) & 0xFF).encode() for i in reversed(range(size))])

def os2ip(X):
    """
        bytes -> int

        Versão inversa do i2osp, é utilizada apenas na RSA.
    """
    X.reverse()
    x = 0
    for i in range(len(X)):
        x += X[i] * 256 ^ i
    return x

def mgf1(input_str, size):
    """
        bytes, size -> bytes

        Função de de geração de máscara do padrão PKCS#1.
    """
    counter = 0
    output = b""
    while len(output) < size:
        C = i2osp(counter, 4)
        output += hashlib.sha3_256(input_str + C).digest()
        counter += 1
    return output[:size]

# 
def OAEPCypher(message, label="", k = 256):
    """
        bytes, str(optional), int(optional) -> bytes

        Cifra OAEP. Recebe uma mensagem bytes e retorna um
        novo bloco, que é maior que a mensagem original.
    """

    #Hash da label
    lHash = hashlib.sha3_256(label.encode()).digest()

    #criação do padding de tamanho k - mLen -2hLen - 2 e transforma em bytes.
    padding = ('0'*(k-len(message)-2*len(lHash)-2)).encode()
    
    #criação do db, um bloco que contém a label, padding, identificador 0x01 e a mensagem
    db = lHash + padding + int(0x01).to_bytes(1,byteorder='big') + message

    #criação de uma 'seed', que é uma string randomica de tamanho hLen
    #é a parte que transforma o RSA em um algoritmo seguro.    
    seed = int(random.getrandbits(len(lHash)*8)).to_bytes(len(lHash), byteorder='big')
    
    #Máscara gerada para realizar o xor com o db.
    dbmask = mgf1(seed, k-len(lHash)-1)

    #máscara de DB com DBmask
    maskedb = int.from_bytes(db,byteorder='big') ^ int.from_bytes(dbmask, byteorder='big')
    maskedbits = maskedb.to_bytes(k-len(lHash)-1, byteorder='big')

    #Tendo mascarado o db original, precisamos passar por outro processo para fazer uma nova máscara.
    #Desta vez é com a seed.
    seedMask = mgf1(maskedbits, len(lHash))

    maskedseed = (int.from_bytes(seed, byteorder='big') ^ int.from_bytes(seedMask, byteorder='big')).to_bytes(len(lHash), byteorder='big')

    #Por fim, juntamos os dois blocos mascarados com um identificador inicial 0x00.
    return int(0x00).to_bytes(1, byteorder='big') + maskedseed + maskedbits

def OAEPDecypher(EM, label="", k = 256):
    """
        bytes, str(optional), int(optional) -> bytes

        Decifração do OAEP. Desta vez recebe o bloco cifrado EM.
        Não só desfaz o processo de cifra do OAEP, como também
        checa se a mensagem não foi maculada.
    """
    #Hash da label
    lHash = hashlib.sha3_256(label.encode()).digest()

    #Começamos separando os dois blocos que importam do EM, maskedSeed e maskeDB.
    maskedseed = EM[1:len(lHash)+1]

    maskedb = EM[len(lHash) + 1:]

    #Após a recuperação da maskedseed, é 'trivial' recuperar a seedMask
    seedMask = mgf1(maskedb , len(lHash))

    #E igualmente a seed original, dado que estamos literalmente fazendo o processo inverso da cifra.
    seed = int.from_bytes(maskedseed, byteorder='big') ^ int.from_bytes(seedMask, byteorder='big')
    seedbits = seed.to_bytes(max(1,math.ceil(seed.bit_length()/8)), byteorder='big')

    dbmask = mgf1(seedbits, k - len(lHash) -1)

    db = int.from_bytes(maskedb, byteorder='big') ^ int.from_bytes(dbmask, byteorder='big')
    dbits = db.to_bytes(max(1,math.ceil(db.bit_length()/8)), byteorder='big')

    #Hash da label que recuperamos de db. 
    lHashl = dbits[:len(lHash)]

    #processo de reconhecer quando o padding acaba.
    i = len(lHash)
    while(i < len(dbits) and dbits[i] == 48):
        i+=1
    
    """
        é aqui que a decifração se torna diferente da cifração.
        checamos se ou o bit de identificação 0x01 foi perdido ou
        se os hashs das labels são diferentes. Caso sejam, printa
        erro e retorna uma string vazia.
    """
    if i == len(dbits) or lHash != lHashl:
        print("Decryption error OEAP")
        return ''
    
    #finalmente conseguimos recuperar a mensagem original.
    message = dbits[i+1:]
    
    return message

l = OAEPCypher('Téâãstes Bons Belos Bonitos :^)'.encode())
#print(l)
r = OAEPDecypher(l).decode()
print(r)
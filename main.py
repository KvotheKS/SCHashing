import random
import math

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

RSA('Téâãstes Bons Belos Bonitos :^)')
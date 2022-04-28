import RSA
import AES
import secrets
import hashlib
import base64
import math

def CypherProtocol(message, pk, sk, nonce):
    """
        str, (e,n), (d,n), bytes -> (bytes(base64), bytes(base64), bytes(base64))
    """
    #Transformando a mensagem inicial em bytes.
    message = message.encode()
    
    #geração da chave de sessão para o AES.
    sessionK = secrets.token_bytes(16)

    #Cálculo do hash da mensagem em claro.
    mHash = hashlib.sha3_256(message).digest()

    #Cifra do Hash da mensagem usando a chave privada do RSA.
    HashCypher = RSA.to_bytes( RSA.RSACypher( int.from_bytes(mHash, byteorder='big') , sk) )
 
    #Cifra da mensagem utilizando o AES.
    CypherText = AES.encryptCTR(message, sessionK, nonce)
    
    #Cifra da chave de sessão tanto com OAEP quanto com RSA.
    CypherSession = RSA.RSAOAEPCypher(sessionK, pk)

    #codificando tudo em base64
    return (base64.b64encode(HashCypher), base64.b64encode(CypherText), 
        base64.b64encode(CypherSession))

def DecypherProtocol(HashCypher, CypherText, CypherSession,pk, sk, nonce):
    #Parsing da mensagem de base64 para bytes.
    HashCypher = base64.b64decode(HashCypher)
    CypherText = base64.b64decode(CypherText)
    CypherSession = base64.b64decode(CypherSession)

    #Decifrando a chave de sessão do AES.
    sessionK = RSA.RSAOAEPDecypher(CypherSession, sk)
    
    #Recuperamos o Hash da mensagem utilizando RSA.
    mHash = RSA.to_bytes(RSA.RSADecypher(int.from_bytes(HashCypher, byteorder='big'), pk))
    
    print(CypherText, sessionK)
    #Recuperamos a mensagem usando AES.
    message = AES.decryptCTR(CypherText, sessionK, nonce)

    #Cálculo de hash da mensagem recuperada
    rmHash = hashlib.sha3_256(message).digest()

    #Comparação do Hash recebido com o Hash inicial da mensagem.
    if rmHash == mHash:
        print("Yay deu certo :)")
    else:
        print("NOOOOOOOOOOOOOO")

    return message.decode()

def FullProtocol(message):
    
    #Geração de Chaves assimétricas pelo padrão RSA.
    pk, sk = RSA.RSAKeys()

    #Geração de um nonce para calculos do AES-CTR.
    nonce = AES.getNonce(16)

    #Resultado da cifração por parte do transmissor.
    HashCypher, CypherText, CypherSession = CypherProtocol(message, pk, sk, nonce)

    #Resultado da decifração por parte do receptor.
    receptor = DecypherProtocol(HashCypher, CypherText, 
                                CypherSession, pk, sk, nonce)

    print(receptor)

FullProtocol('kappa')
import RSA
import AES
import secrets
import hashlib
import base64

def appendCypher(sessionK, mHash, CypherHash, CypherText, CypherSession):
    """
        bytes, bytes, bytes, bytes, bytes -> _
    
        Serve para pegar as principais informações do processo da cifração do programa.
    """
    hyphen = '------------'
    nl = '\n\n\n'
    lsInfo = [sessionK, mHash, CypherHash, CypherText, CypherSession]
    lsNames= ["sessionK", "mHash", "CypherHash", "CypherText", "CypherSession"]
    for i in range(len(lsInfo)):
        cypherOut.write(hyphen + lsNames[i] + hyphen + nl + str(lsInfo[i]) + nl)

def appendDecypher(sessionK, mHash, rmHash, message):
    """
        bytes, bytes, bytes, bytes -> _
        
        Serve para pegar as principais informações do processo da decifração do programa.
    """
    hyphen = '------------'
    nl = '\n\n\n'
    lsInfo = [sessionK, mHash, rmHash, message]
    lsNames= ["sessionK", "mHash", "rmHash", "message"]
    for i in range(len(lsInfo)):
        decypherOut.write(hyphen + lsNames[i] + hyphen + nl + str(lsInfo[i]) + nl)

def CypherProtocol(message, pk, sk, nonce):
    """
        str, (e,n), (d,n), bytes -> (bytes(base64), bytes(base64), bytes(base64))

        Função que simula o processo de cifração por parte do remetente da mensagem
        Entrada:
            message -> Mensagem a ser cifrada
            pk -> Chave pública do RSA
            sk -> Chave privada do RSA
            nonce -> Valor do vetor inicial do AES
        Saída:
            Retorna o Hash da mensagem em claro cifrado usando RSA com a sk, a mensagem cifrada
            utilizando AES no modo CTR com uma chave de sessão e a chave de sessão cifrada usando
            RSAOAEP. Todos os três são codificados em BASE64
    """
    # Transformando a mensagem inicial em bytes.
    message = message.encode()
    
    # Geração da chave de sessão para o AES.
    sessionK = secrets.token_bytes(16)

    # Cálculo do hash da mensagem em claro.
    mHash = hashlib.sha3_256(message).digest()

    # Cifra do Hash da mensagem usando a chave privada do RSA.
    CypherHash = RSA.to_bytes( RSA.RSACypher( int.from_bytes(mHash, byteorder='big') , sk) )
    CypherHash = base64.b64encode(CypherHash)
    # Cifra da mensagem utilizando o AES.
    CypherText = AES.encryptCTR(message, sessionK, nonce)
    CypherText = base64.b64encode(CypherText)

    # Cifra da chave de sessão tanto com OAEP quanto com RSA.
    CypherSession = RSA.RSAOAEPCypher(sessionK, pk)
    CypherSession = base64.b64encode(CypherSession)

    appendCypher(sessionK, mHash, CypherHash, CypherText, CypherSession)

    # Vale notar que todos esses elementos tomaram encoding em Base64, 
    # assim como requisitado 
    return CypherHash, CypherText, CypherSession

def DecypherProtocol(CypherHash, CypherText, CypherSession, pk, sk, nonce):
    """
        bytes(base64), bytes(base64), bytes(base64), (e,n), (d,n), bytes -> str || None

        Função que simula o processo de decifração por parte do destinatário da mensagem
        Entrada:
            CypherHash -> Hash cifrado da mensagem em claro
            CypherText -> A mensagem cifrada
            CypherSession -> Chave de sessão cifrada
            pk -> Chave pública do RSA
            sk -> Chave privada do RSA
            nonce -> Valor do vetor inicial do AES
        Saída:
            Retorna a mensagem decifrada caso o cálculo do Hash da mensagem decifrada seja igual
            ao Hash da mensagem em claro que foi enviado. Caso contrário, retorna None
    """
    # Parsing da mensagem de BASE64 para Bytes.
    CypherHash = base64.b64decode(CypherHash)
    CypherText = base64.b64decode(CypherText)
    CypherSession = base64.b64decode(CypherSession)

    # Decifrando a chave de sessão do AES.
    sessionK = RSA.RSAOAEPDecypher(CypherSession, sk)
    
    # Recuperamos o Hash da mensagem utilizando RSA.
    mHash = RSA.to_bytes(RSA.RSADecypher(int.from_bytes(CypherHash, byteorder='big'), pk))

    # Recuperamos a mensagem usando o AES no modo CTR.
    message = AES.decryptCTR(CypherText, sessionK, nonce)

    # Cálculo de Hash da mensagem recuperada
    rmHash = hashlib.sha3_256(message).digest()
    
    appendDecypher(sessionK, mHash, rmHash, message.decode())
    
    # Comparação do Hash recebido com o Hash inicial da mensagem.
    if rmHash == mHash:
        print("Arquivo verificado! O cálculo do hash da mensagem recuperada é igual ao hash enviado.")
        return message.decode()
    else:
        print("ERRO! O cálculo do hash da mensagem recuperada não condiz com o hash enviado!!!")
        return None
    
    

def FullProtocol(message):
    """
        Função que simula a comunicação entre um remetente e um destinatário. É nela em que serão
        geradas as chaves pública e privada do RSA assim como o nonce (vetor inicial do AES). Essa
        função realiza a cifração de uma mensagem do remetente e a envia para um destinatário, que
        por sua vez decifra a mensagem recebida e verifica se ela está correta.
        Entrada:
            message -> Mensagem a ser enviada
    """
    print("Fazendo a cifração da mensagem...")
    
    # Geração das chaves assimétricas pelo padrão RSA.
    pk, sk = RSA.RSAKeys()

    # Geração de um nonce para os calculos do AES-CTR.
    nonce = AES.getNonce(16)

    # Resultado da cifração por parte do transmissor.
    CypherHash, CypherText, CypherSession = CypherProtocol(message, pk, sk, nonce)
    
    print("Mensagem cifrada a ser enviada:")
    print(CypherText)

    # Resultado da decifração por parte do receptor.
    recoverMessage = DecypherProtocol(CypherHash, CypherText, CypherSession, pk, sk, nonce)

    print("Messagem decifrada recebida:")
    print(recoverMessage)

print("Informe o nome do arquivo com a mensagem a ser transmitida: ", end="")
fileName = input()

with open(fileName, "r", encoding='utf-8') as arquivo:
    message = arquivo.read()

cypherOut = open('CypherOutput.txt', 'w', encoding='utf-8')
decypherOut = open('DecypherOutput.txt', 'w', encoding='utf-8')

FullProtocol(message)

cypherOut.close()
decypherOut.close()
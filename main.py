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

    #Recuperamos a mensagem usando AES.
    message = AES.decryptCTR(CypherText, sessionK, nonce)

    #Cálculo de hash da mensagem recuperada
    rmHash = hashlib.sha3_256(message).digest()

    #Comparação do Hash recebido com o Hash inicial da mensagem.
    if rmHash == mHash:
        print("Arquivo verificado! O cálculo do hash da mensagem recuperada é igual ao hash enviado.")
        return message.decode()
    else:
        print("ERRO! O cálculo do hash da mensagem recuperada não condiz com o hash enviado!!!")
        return None

def FullProtocol(message):
    
    #Geração de Chaves assimétricas pelo padrão RSA.
    pk, sk = RSA.RSAKeys()

    #Geração de um nonce para calculos do AES-CTR.
    nonce = AES.getNonce(16)

    #Resultado da cifração por parte do transmissor.
    HashCypher, CypherText, CypherSession = CypherProtocol(message, pk, sk, nonce)
    print(CypherText)

    #Resultado da decifração por parte do receptor.
    receptor = DecypherProtocol(HashCypher, CypherText, 
                                CypherSession, pk, sk, nonce)

    print("Messagem recebida:")
    print(receptor)

FullProtocol('Os amigos do maestro querem que dificilmente se possa acha obra tão bem acabada. Um ou outro admite certas rudezas e tais ou quais lacunas, mas com o andar da ópera é provável que estas sejam preenchidas ou explicadas, e aquelas desapareçam inteiramente, não se negando o maestro a emendar a obra onde achar que não responde de todo ao pensamento sublime do poeta. Já não dizem o mesmo os amigos deste. Juram que o libreto foi sacrificado, que a partitura corrompeu o sentido da letra, e, posto seja bonita em alguns lugares, e trabalhada com arte em outros, é absolutamente diversa e até contrária ao drama. O grotesco, por exemplo, não está no texto do poeta; é uma excrescência para imitar as Mulheres Patuscas de Windsor. Este ponto é contestado pelos satanistas com alguma aparência de razão. Dizem eles que, ao tempo em que o jovem Satanás compôs a grande ópera, nem essa farsa nem Shakespeare eram nascidos. Chegam a afirmar que o poeta inglês não teve outro gênio senão transcrever a letra da ópera, com tal arte e fidelidade, que parece ele próprio o autor da composição; mas, evidentemente, é um plagiário.')
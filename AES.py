import secrets
import math

# Quantidade de rodadas de transformações (para chave de 128 bits, usa-se 10 rodadas)
N_ROUNDS = 10

# Lookup table -> Uma caixa de substituição que mapeia uma entrada de 8 bits para um saída de 8 bits
S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

# Constante de rodada usada pela função de geração das chaves de rodada do AES
RCON = (
    [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
)

# Matriz fixa no Corpo de Galois GF(2^8)
GF_MATRIX = (
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
)

def printHex(matrix):
    """
        Função utilizada para printar uma matrix 4x4 usando valores hexadecimais
        Entrada:
            matrix -> matriz 4x4 de inteiros
    """
    for i in range(4):
        for j in range(4):
            print(hex(matrix[j][i]), end=" ")
        print()
    print()

def listToMatrix(list, n, mode=0):
    """
        Função que converte uma lista para uma matriz NxN
        Entrada:
            list -> lista a ser transformada
            n -> tamanho da matriz
            mode -> Indica se a lista vai ser quebrada em colunas da matriz (0) ou linhas da matriz (1)
        Saída:
            matriz NxN montada a partir de colunas ou de linhas
    """
    if mode != 0:
        return [[list[n*i + j] for i in range(n)] for j in range(n)]
    return [[list[i + n*j] for i in range(n)] for j in range(n)]

def matrixToList(matrix, n, mode=0):
    """
        Função que converte uma matriz para uma lista de tamnho NxN
        Entrada:
            matrix -> matriz a ser transformada
            n -> tamanho da matriz
            mode -> Indica se a matriz é um matriz organizada em colunas (0) ou em linhas (1)
        Saída:
            lista de tamanho NxN montada a partir da matriz em colunas ou em linhas
    """
    if mode != 0:
        return [matrix[j][i] for i in range(n) for j in range(n)]
    return [matrix[i][j] for i in range(n) for j in range(n)]

def galoisMul(a, b):
    """
        Função que realiza a multiplicação no Corpo de Galois GF(2^8)
        Entrada:
            a -> elemento do estado a ser multiplicado
            b -> elemento da matriz GF_MATRIX que multiplica a (pode ser 1, 2 ou 3)
        Saída:
            Resultado da multiplicação de a x b
    """
    if b == 1:
        # Retorna o próprio a, por ser uma multiplicação por 1
        return a
    # Realiza um shift à esquerda em a e mascara o bit de transbordo
    tmp = (a << 1) & 0xFF
    if b == 2:
        # Retorna o valor de a shiftado se for menor que 128 ou retorna o XOR desse valor com 0x1B
        return tmp if a < 128 else tmp ^ 0x1B
    if b == 3:
        # Retorna o XOR da multiplicação de a por 2 com o próprio a
        return galoisMul(a, 2) ^ a

def rotWord(column):
    """
        Função que realiza a rotação de uma coluna e realiza a substituição dos valores usando a S_BOX
        Entrada:
            column -> coluna a ser rotacionada e substituída
        Saída:
            rot_word -> nova coluna resultante da operação
    """
    # Pega os elementos a partir do segundo elemento da coluna e faz a substituição
    rot_word = [S_BOX[column[i]] for i in range(1, len(column))]
    # Pega o primeiro elemento da coluna, o substitui usando S_BOX e adiciona ele ao final da nova coluna
    rot_word += [S_BOX[column[0]]]
    return rot_word

def keyExpansion(masterKey):
    """
        Função que computa as chaves de cada uma das N_ROUNDS rodadas
        Entrada:
            masterKey -> chave principal passada para o AES
        Saída:
            roundKeys -> lista de todas as chaves de rodadas no formato de matriz de colunas
    """
    # Transforma a masterKey em matriz de colunas
    masterKey = listToMatrix(list(masterKey), 4)
    # Adiciona ela temporariamente como sendo uma chave de rodada
    roundKeys = [masterKey]

    # Para cada uma das rodadas, criamos uma chave baseada na chave anterior
    for i in range(N_ROUNDS):
        # Pega a última chave computada
        prevMatrix = roundKeys[-1]
        auxMatrix = []
        for j in range(4):
            # Se for a primeira coluna da nova chave
            if j == 0:
                # Rotaciona ele verticalmente e substitui usando a S_BOX
                fstColumn = rotWord(prevMatrix[-1])
                # Para cada elemento da coluna faz um XOR com esse elemento, o elemento da coluna 0 
                # da chave anterior e o elemento da constante de rodada atual
                for k in range(4):
                    fstColumn[k] = prevMatrix[0][k] ^ fstColumn[k] ^ RCON[i][k]
                # Adiciona a primeira coluna da nova chave de rodada
                auxMatrix.append(fstColumn)
            else:
                column = []
                # Para as demais colunas, só precisa fazer um XOR com o elemento da coluna j da chave anterior
                # e o elemento da coluna anterior da nova chave
                for k in range(4):
                    column.append(prevMatrix[j][k] ^ auxMatrix[-1][k])
                # Adiciona a coluna da nova chave de rodada
                auxMatrix.append(column)
        # Com a matriz da chave feita, temos uma nova chave de rodada
        roundKeys.append(auxMatrix)
    
    # Tiramos a masterKey da lista de chaves de rodada
    roundKeys.pop(0)

    return roundKeys

def addRoundKey(state, roundKey):
    """
        Função que realiza a combinação do Estado com uma chave de Rodada
        A combinação é feita fazendo um XOR elemento a elemento do Estado com a chave
        Entrada:
            state -> Estado atual da mensagem sendo cifrada
            roundKey -> Chave da rodada atual
    """
    for i in range(len(state)):
        for j in range(len(state)):
            state[i][j] ^= roundKey[i][j]

def subByte(state):
    """
        Função que realiza a substituição de cada elemento do Estado pelo seu equivalente através da S_BOX
        Entrada:
            state -> Estado atual da mensagem sendo cifrada
    """
    for i in range(len(state)):
        for j in range(len(state)):
            state[i][j] = S_BOX[state[i][j]]

def shiftRows(state):
    """
        Função que realiza um shift circular nas linhas da matriz do Estado
        A linha i se desloca i elementos para a esquerda de forma circular
        Entrada:
            state -> Estado atual da mensagem sendo cifrada
        Saída:
            Matriz em colunas com as linhas shiftadas
    """
    # Quantidade de colunas do estado
    stateSize = len(state)
    # Converte o Estado de uma matriz de colunas para uma matriz de linhas
    state = listToMatrix(matrixToList(state, stateSize), stateSize, 1)
    # Para cada linha começando da segunda, faz o shift circular
    for i in range(1, stateSize):
        state[i] = state[i][i:] + state[i][:i]
    # Retorna uma matriz de colunas
    return listToMatrix(matrixToList(state, stateSize, 1), stateSize)

def mixColumns(state):
    """
        Função que realiza uma transformação linear nas colunas com a matriz GF_MATRIX
        Essa transformação consiste em multiplicar GF_MATRIX por cada coluna do Estado
        Entrada:
            state -> Estado atual da mensagem sendo cifrada
        Saída:
            result -> Matriz em colunas com as colunas transformadas
    """
    # Matriz auxiliar iniciada com 0 (0 é a identidade da operação XOR)
    result = [[0 for _ in range(len(state))] for _ in range(len(state))]

    # Realiza multiplicação das matrizes
    for i in range(len(state)):
        for j in range(len(GF_MATRIX)):
            for k in range(len(state)):
                # A multiplicação dos elementos é feita usando a multiplicação no Corpo de Galois
                # e a adição é feita usando a operação XOR
                result[i][j] ^= galoisMul(state[i][k], GF_MATRIX[j][k])

    return result

def encryptAES(plaintext, masterKey):
    """
        Função de cifração usando o AES
        Entrada:
            plaintext -> mensagem a ser cifrada, deve estar em string de bytes
            masterKey -> chave usada para fazer a cifração, deve estar em string de bytes
        Saída:
            ciphertext -> mensagem cifrada pelo AES
    """
    # Computa as chaves de rodada
    roundKeys = keyExpansion(masterKey)
    # Transforma a mensagem em uma matriz
    ciphertext = listToMatrix(list(plaintext), 4)

    # Realiza a etapa de addRoundKey com o plaintext e a chave principal
    addRoundKey(ciphertext, listToMatrix(list(masterKey), 4))

    # Fazemos esses 4 passos por N_ROUNDS-1 rodadas
    for i in range(N_ROUNDS-1):
        # Realiza a etapa de subByte com o Estado
        subByte(ciphertext)
        # Realiza a etapa de shiftRows com o Estado
        ciphertext = shiftRows(ciphertext)
        # Realiza a etapa de mixColumns com o Estado
        ciphertext = mixColumns(ciphertext)
        # Realiza a etapa de addRoundKey com o plaintext e a chave de rodada atual
        addRoundKey(ciphertext, roundKeys[i])
    
    # Na última rodada não realiza a etapa de mixColumns
    subByte(ciphertext)
    ciphertext = shiftRows(ciphertext)
    addRoundKey(ciphertext, roundKeys[-1])

    # Retorna o resultado do processo de cifração
    return bytes(matrixToList(ciphertext, 4))

def padding(plaintext):
    """
        Função que adiciona um padding à mensagem usando PKCS#7 padding
        No caso, os elementos do padding são justamente o tamanho do mesmo
        Se a mensagem já tiver 16 bytes, é adicionado um bloco inteiro de 16 bytes como padding
        Entrada:
            plaintext -> mensagem que sofrerá o padding
        Saída:
            Mensagem de tamanho múltiplo de 16 bytes
    """
    # Calcula o tamanho do padding
    paddingLen = 16 - (len(plaintext) % 16)
    # Adiciona paddingLen bytes com valor igual a paddingLen na mensagem
    paddingBytes = bytes([paddingLen] * paddingLen)
    return plaintext + paddingBytes

def unpadding(plaintext):
    """
        Função que remove um padding da mensagem usando PKCS#7 padding
        Entrada:
            plaintext -> mensagem com padding no final dela
        Saída:
            Mensagem sem o padding
    """
    # Pega o tamanho do padding
    paddingLen = plaintext[-1]
    # A mensagem original vai ser a mensagem sem os paddingLen últimos bytes
    message, plaintext = plaintext[:-paddingLen], plaintext[-paddingLen:]
    return message

def getNonce(n):
    """
        Função que gera uma string de bytes aleatória de n bytes que deve ser usada uma única vez
        Entrada:
            n -> número de bytes
        Saída:
            String de n bytes aleatória
    """
    return secrets.token_bytes(n)

def increaseCounter(counter):
    """
        Função que incrementa o contador do CTR em 1
        Entrada:
            counter -> contador do CTR
        Saída:
            Contador + 1
    """
    # Converte o contador para um número inteiro
    auxCount = int.from_bytes(counter, byteorder='big')
    # Icrementa o contador
    auxCount += 1
    # Retorna o contador + 1 como uma string de bytes
    return auxCount.to_bytes(max(1, math.ceil(auxCount.bit_length()/8)), byteorder='big')

def splitIntoBlocks(plaintext, sizeBlock=16):
    """
        Função que quebra uma mensagem em blocos de sizeBlock bytes
        Entrada:
            plaintext -> mensagem a ser quebrada
            sizeBlock -> tamanho de cada bloco em bytes
        Saída:
            blocks -> lista com todos os blocos gerados pela quebra
    """
    blocks = []
    # A mensagem será dividida em len(plaintext) // sizeBlock blocos
    for i in range(len(plaintext) // sizeBlock):
        # Cria um bloco
        blocks.append(plaintext[sizeBlock*i : sizeBlock*(i+1)])
    return blocks

def unionBlocks(blocks):
    """
        Função que une vários blocos de uma mensagem para uma string de bytes
        Entrada:
            blocks -> lista com os blocos da mensagem
        Saída:
            union -> resultado da união desses blocos em uma string de bytes
    """
    # Pega o primeiro bloco
    union = blocks[0]
    # Depois concatena cada bloco no final
    for i in range(1, len(blocks)):
        union += blocks[i]
    return union

def xorBytes(byteStr1, byteStr2):
    """
        Função que realiza XOR elemento a elemento entre duas string de bytes
        Entrada:
            byteStr1 -> string de bytes
            byteStr2 -> string de bytes
        Saída:
            Resultado do XOR byte a byte das duas string de bytes
    """
    return bytes([byteStr1[i] ^ byteStr2[i] for i in range(len(byteStr1))])

def encryptCTR(plaintext, key, iv):
    """
        Função que realiza a cifração do AES no modo CTR
        Entrada:
            plaintext -> mensagem a ser cifrada
            key -> chave usada para cifrar a mensagem
            iv -> vetor inicial é um nonce (number once) e será o valor inicial do contador
        Saída:
            ciphertext -> mensagem cifrada
    """
    # Adiciona o padding da mensagem
    plaintext = padding(plaintext)
    # Quebra a mensagem em blocos
    plaintextBlocks = splitIntoBlocks(plaintext)

    blocks = [] # Lista de blocos da mensagem cifrada
    counter = iv # Inicia o contador com o valor do vetor inicial
    for plaintextBlock in plaintextBlocks:
        # Cifra o contador com o AES usando key como chave e depois faz um XOR byte a byte
        # com o bloco de mensagem
        block = xorBytes(plaintextBlock, encryptAES(counter, key))
        # Adiciona o bloco cifrado na lista de blocos da mensagem cifrada
        blocks.append(block)
        # Icrementa o contador
        counter = increaseCounter(counter)
    
    # Converte a lista de blocos para uma string de bytes
    return unionBlocks(blocks)

def decryptCTR(ciphertext, key, iv):
    """
        Função que realiza a decifração do AES no modo CTR
        Entrada:
            ciphertext -> mensagem a ser decifrada
            key -> chave usada para decifrar a mensagem
            iv -> vetor inicial é um nonce (number once) e será o valor inicial do contador
        Saída:
            plaintext -> mensagem decifrada (mensagem origianl)
    """
    # Quebra a mensagem cifrada em blocos
    ciphertextBlocks = splitIntoBlocks(ciphertext)

    blocks = [] # Lista de blocos da mensagem original
    counter = iv # Inicia o contador com o valor do vetor inicial
    for ciphertextBlock in ciphertextBlocks:
        # Cifra o contador com o AES usando key como chave e depois faz um XOR byte a byte
        # com o bloco de mensagem cifrada
        block = xorBytes(ciphertextBlock, encryptAES(counter, key))
        # Adiciona o bloco decifrado na lista de blocos da mensagem original
        blocks.append(block)
        # Icrementa o contador
        counter = increaseCounter(counter)
    
    # Remove o padding da mensagem e converte a lista de blocos para uma string de bytes
    return unpadding(unionBlocks(blocks))

if __name__ == "__main__":
    x = 0x3243f6a8885a308d313198a2e0370734
    y = 0x2b7e151628aed2a6abf7158809cf4f3c

    plaintext = x.to_bytes(max(1, math.ceil(x.bit_length()/8)), byteorder='big')
    key = y.to_bytes(max(1, math.ceil(y.bit_length()/8)), byteorder='big')

    # z = encryptAES(plaintext, key)
    # print(int.from_bytes(bytes(matrixToList(z, 4)), byteorder='big'))
    # print(z)

    nonce = getNonce(16)

    # print("plaintext =", plaintext)
    print("plaintext =", list(plaintext))
    # print(int.from_bytes(nonce, byteorder='big'))

    ciphertext = encryptCTR(plaintext, key, nonce)
    # print("ciphertext =", ciphertext)
    print("ciphertext =", list(ciphertext))

    answertext = decryptCTR(ciphertext, key, nonce)
    # print("answertext =", answertext)
    print("answertext =", list(answertext))
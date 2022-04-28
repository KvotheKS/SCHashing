import secrets
import math

N_ROUNDS = 10

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

RCON = (
    [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
)

GF_MATRIX = (
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
)

def printHex(matrix):
    for i in range(4):
        for j in range(4):
            print(hex(matrix[j][i]), end=" ")
        print()
    print()

def listToMatrix(list, n, mode=0):
    if mode != 0:
        return [[list[n*i + j] for i in range(n)] for j in range(n)]
    return [[list[i + n*j] for i in range(n)] for j in range(n)]

def matrixToList(matrix, n, mode=0):
    if mode != 0:
        return [matrix[j][i] for i in range(n) for j in range(n)]
    return [matrix[i][j] for i in range(n) for j in range(n)]

def galoisMul(a, b):
    if b == 1:
        return a
    tmp = (a << 1) & 0xFF
    if b == 2:
        return tmp if a < 128 else tmp ^ 0x1B
    if b == 3:
        return galoisMul(a, 2) ^ a

def rotWord(column):
    rot_word = [S_BOX[column[i]] for i in range(1, len(column))]
    rot_word += [S_BOX[column[0]]]
    return rot_word

def keyExpansion(masterKey):
    masterKey = listToMatrix(list(masterKey), 4)
    roundKeys = [masterKey]

    for i in range(N_ROUNDS):
        prevMatrix = roundKeys[-1]
        auxMatrix = []
        for j in range(4):
            if j == 0:
                fstColumn = rotWord(prevMatrix[-1])
                for k in range(4):
                    fstColumn[k] = prevMatrix[0][k] ^ fstColumn[k] ^ RCON[i][k]
                auxMatrix.append(fstColumn)
            else:
                column = []
                for k in range(4):
                    column.append(prevMatrix[j][k] ^ auxMatrix[-1][k])
                auxMatrix.append(column)
        roundKeys.append(auxMatrix)
    roundKeys.pop(0)

    return roundKeys

def addRoundKey(state, roundKey):
    for i in range(len(state)):
        for j in range(len(state)):
            state[i][j] ^= roundKey[i][j]

def subByte(state):
    for i in range(len(state)):
        for j in range(len(state)):
            state[i][j] = S_BOX[state[i][j]]

def shiftRows(state):
    stateSize = len(state)
    state = listToMatrix(matrixToList(state, stateSize), stateSize, 1)
    for i in range(1, stateSize):
        state[i] = state[i][i:] + state[i][:i]
    return listToMatrix(matrixToList(state, stateSize, 1), stateSize)

def mixColumns(state):
    result = [[0 for _ in range(len(state))] for _ in range(len(state))]

    for i in range(len(state)):
        for j in range(len(GF_MATRIX)):
            for k in range(len(state)):
                result[i][j] ^= galoisMul(state[i][k], GF_MATRIX[j][k])

    return result

def encryptAES(plaintext, masterKey):
    roundKeys = keyExpansion(masterKey)
    ciphertext = listToMatrix(list(plaintext), 4)

    addRoundKey(ciphertext, listToMatrix(list(masterKey), 4))

    for i in range(N_ROUNDS-1):
        subByte(ciphertext)
        ciphertext = shiftRows(ciphertext)
        ciphertext = mixColumns(ciphertext)
        addRoundKey(ciphertext, roundKeys[i])
    
    subByte(ciphertext)
    ciphertext = shiftRows(ciphertext)
    addRoundKey(ciphertext, roundKeys[-1])

    return bytes(matrixToList(ciphertext, 4))

def padding(plaintext):
    paddingLen = 16 - (len(plaintext) % 16)
    paddingBytes = bytes([paddingLen] * paddingLen)
    return plaintext + paddingBytes

def unpadding(plaintext):
    paddingLen = plaintext[-1]
    message, plaintext = plaintext[:-paddingLen], plaintext[-paddingLen:]
    return message

def getNonce(n):
    return secrets.token_bytes(n)

def increaseCounter(counter):
    auxCount = int.from_bytes(counter, byteorder='big')
    auxCount += 1
    return auxCount.to_bytes(max(1, math.ceil(auxCount.bit_length()/8)), byteorder='big')

def splitIntoBlocks(plaintext, sizeBlock=16):
    blocks = []
    for i in range(len(plaintext) // sizeBlock):
        blocks.append(plaintext[sizeBlock*i : sizeBlock*(i+1)])
    return blocks

def unionBlocks(blocks):
    union = blocks[0]
    for i in range(1, len(blocks)):
        union += blocks[i]
    return union

def xorBytes(byteStream1, byteStraem2):
    return bytes([byteStream1[i] ^ byteStraem2[i] for i in range(len(byteStream1))])

def encryptCTR(plaintext, key, iv):
    plaintext = padding(plaintext)
    plaintextBlocks = splitIntoBlocks(plaintext)

    blocks = []
    counter = iv
    for plaintextBlock in plaintextBlocks:
        block = xorBytes(plaintextBlock, encryptAES(counter, key))
        blocks.append(block)
        counter = increaseCounter(counter)
    
    return unionBlocks(blocks)

def decryptCTR(ciphertext, key, iv):
    ciphertextBlocks = splitIntoBlocks(ciphertext)

    blocks = []
    counter = iv
    for ciphertextBlock in ciphertextBlocks:
        block = xorBytes(ciphertextBlock, encryptAES(counter, key))
        blocks.append(block)
        counter = increaseCounter(counter)
    
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
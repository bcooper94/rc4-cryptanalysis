import pickle
import os.path
import numpy as np
from Crypto.Cipher import ARC4
from Crypto import Random
from math import log
import matplotlib.pyplot as plt

KEY_SIZE = 16
TOP_PASSWORDS = 100000
ENCRYPTIONS_SAMPLE_PICKLE = 'encryptedPws.p'
SINGLE_PW_PICKLE = 'singlePw.p'
BYTE_DIST_PICKLE = 'byteDist.p'
KEYSTREAM_DIST_PICKLE = 'keystream.p'
TLS_FINISH = 'TLS Finished: password='

rand = Random.new()


def x_or(byteArrOne, byteArrTwo):
    return bytearray(
        [byteOne ^ byteTwo for byteOne, byteTwo
         in zip(byteArrOne, byteArrTwo)])


def generateKeystreamDist(password, count, keyReuses, forceReload=False):
    pickledFile = '{}_{}'.format(password, KEYSTREAM_DIST_PICKLE)

    if not forceReload and os.path.isfile(pickledFile):
        print('generateKeystreamDist loading pickled file')
        keystreamDist = pickle.load(open(pickledFile, 'rb'))
    else:
        print('Regenerating keystream distribution')

        byteSize = 256
        message = TLS_FINISH + password
        messageLen = len(message)
        messageBytes = bytearray(bytes(message))
        step = int(count / 10)
        curStep = step
        keystreamDist = np.zeros(shape=(messageLen, byteSize), dtype=int)

        for keyCount in range(count):
            key = rand.read(KEY_SIZE)
            rc4 = ARC4.new(key)

            if keyCount == curStep:
                print('{}% done'.format(100 * curStep / count))
                curStep += step

            for keyReuse in range(keyReuses):
                encryptedMsg = bytearray(bytes(rc4.encrypt(message)))
                keystream = x_or(encryptedMsg, messageBytes)
                for position, byte in enumerate(keystream):
                    keystreamDist[position][byte] += 1

        pickle.dump(keystreamDist, open(pickledFile, 'wb'))
    return keystreamDist


def getKeystreamProbabilityDist(keystreamDist):
    totalByteCounts = np.sum(keystreamDist, axis=1)
    keystreamProbs = np.divide(keystreamDist, totalByteCounts[:, None], dtype=float)
    return keystreamProbs


def graphKeystreamDistByBytePos(keystreamDist, pos):
    plt.plot(keystreamDist[pos, :])
    plt.title('Keystream Byte Frequencies for CT Position {}'.format(pos))
    plt.ylabel('Frequency')
    plt.xlabel('Byte Value')
    axes = plt.gca()
    axes.set_xlim([-5, 270])
    plt.show()


def graphKeystreamDistByByteValue(keystreamDist, byteVal):
    plt.plot(keystreamDist[:, byteVal])
    plt.title('Keystream Byte Frequencies for Byte Value {}'.format(byteVal))
    plt.ylabel('Frequency')
    plt.xlabel('CT Position')
    plt.show()


def generateEncryptionDist(password, count, forceReload=False):
    pickledFile = '{}_{}'.format(password, SINGLE_PW_PICKLE)

    if not forceReload and os.path.isfile(pickledFile):
        print('generateEncryptionDist loading pickled file')
        pwEncryptions = pickle.load(open(pickledFile, 'rb'))
    else:
        print('Regenerating encryption distribution')
        message = TLS_FINISH + password
        encryptedPws = np.ndarray(shape=(count), dtype=object)
        step = int(count / 10)
        curStep = step

        for i in range(count):
            if i == curStep:
                print('{}% done'.format(100 * curStep / count))
                curStep += step
            key = rand.read(KEY_SIZE)
            rc4 = ARC4.new(key)
            encryptedPws[i] = bytearray(bytes(rc4.encrypt(message)))

        pwEncryptions = (encryptedPws, password)
        pickle.dump(pwEncryptions, open(pickledFile, 'wb'))

    return pwEncryptions


# encrypt passwords with randomly generated key
def encryptPassword(password, count):
    message = TLS_FINISH + password
    encryptedPws = np.ndarray(shape=(count, 2), dtype=object)

    for i in range(count):
        key = rand.read(KEY_SIZE)
        rc4 = ARC4.new(key)
        encryptedPws[i][0] = rc4.encrypt(message)
        encryptedPws[i][1] = password
    # return [[rc4.encrypt(password), password] for i in range(count)]
    return encryptedPws


def getEncryptionSamples(passwords, encryptionCount, forceReload=False):
    if not forceReload and os.path.isfile(ENCRYPTIONS_SAMPLE_PICKLE):
        print('loading pickled file')
        matrix = pickle.load(open(ENCRYPTIONS_SAMPLE_PICKLE, 'rb'))
    else:
        print('getEncryptionSamples regenerating encryption samples')
        # samples = [encryptPassword(pw, encryptionCount) for pw in passwords]
        samples = []
        for pw in passwords:
            samples.extend(encryptPassword(pw, encryptionCount))
        # print(samples)
        matrix = np.asmatrix(samples)
        pickle.dump(matrix, open(ENCRYPTIONS_SAMPLE_PICKLE, 'wb'))
    return matrix


# log probabilities of passwords
def computePasswordProbabilities(passwordCounts, totalCount):
    probabilities = {}
    totalProb = log(totalCount)

    for password in passwordCounts:
        probabilities[password] = log(passwordCounts[password]) - totalProb

    return probabilities


def getPasswordCounts(filename):
    probabilities = {}
    totalCount = 0
    with open(filename, 'r') as pwFile:
        for line in pwFile:
            splitLine = line.strip().split()
            if len(splitLine) >= 2:
                count = int(splitLine[0])
                totalCount += count
                password = splitLine[1]
                if password not in probabilities:
                    probabilities[password] = count
                else:
                    probabilities[password] += count

                # don't really care about super uncommon ones now
                if count == 1:
                    break
    return probabilities, totalCount


def getSortedPasswords(passwordProbabilities):
    return sorted([(pw, passwordProbabilities[pw]) for pw in passwordProbabilities],
                  key=lambda val: val[1], reverse=True)


def loadByteProbabilities(password, pwEncryptions=None):
    pickledFile = '{}_{}'.format(password, BYTE_DIST_PICKLE)
    byteSize = 256
    numBytes = len(TLS_FINISH + password)

    if os.path.isfile(pickledFile):
        print('loadByteProbabilities loading pickled file')
        frequencies = pickle.load(open(pickledFile, 'rb'))
    elif pwEncryptions is not None:
        print('loadByteProbabilities regenerating byte frequencies')
        frequencies = np.zeros(shape=(numBytes, byteSize), dtype=int)

        for index, encryption in enumerate(pwEncryptions):
            # print('Encryption len:', len(encryption), encryption)
            for byteNum, byte in enumerate(encryption):
                frequencies[byteNum][int(byte)] += 1
        pickle.dump(frequencies, open(pickledFile, 'wb'))
    else:
        raise ValueError('No pickled byteDist.p found and pwEncryptions is None')
    return frequencies


def graphByteProbabilitiesByBytePos(password, frequencies):
    numBytes = len(TLS_FINISH + password)

    # print('Frequencies: ', frequencies[:5, 0])
    for bytePosition in range(numBytes):
        plt.title('Byte Probabilities for {}'.format(password))
        plt.xlabel('Bytes in CT Position {}'.format(bytePosition))
        plt.ylabel('Frequencies')
        plt.plot(frequencies[bytePosition, :])
        plt.show()


def graphByteFreqsByByteValue(password, frequencies):
    byteSize = 256

    # print('Frequencies: ', frequencies[:5, 0])
    for byte in range(byteSize):
        plt.title('Byte Frequencies for {}'.format(password))
        plt.xlabel('CT Positions'.format(byte))
        plt.ylabel('Frequency of Byte Value {}'.format(byte))
        plt.plot(frequencies[:, byte])
        plt.show()


def graphEntropyByBytePosition(password, frequencies):
    byteSize = 256
    messageLen = len(TLS_FINISH + password)
    expectedCounts = np.mean(frequencies, axis=1)
    total = np.sum(frequencies, axis=1)
    print('Expected:', expectedCounts / total)
    print('Argmax:', np.argmax(frequencies, axis=1))


def getExpectedByteCounts(frequencies):
    return np.mean(frequencies, axis=0)


def graphByteEntropyByByteValue(password, frequencies):
    byteSize = 256
    messageLen = len(TLS_FINISH + password)
    expectedCounts = getExpectedByteCounts(frequencies)
    total = np.sum(frequencies, axis=0)
    print('Total: ', total)


def singleByteBiasEstimateByte(encryptionByteFreqs, keystreamProbDist):
    byteSize = 256
    candidateWeights = np.ndarray(shape=(byteSize), dtype=float)
    candidateDist = np.ndarray(shape=(byteSize), dtype=int)

    for candidateByte in range(byteSize):
        for keyCandidate in range(byteSize):
            candidateDist[keyCandidate] = encryptionByteFreqs[candidateByte ^ keyCandidate]
        candidateWeights[candidateByte] = np.sum(candidateDist * np.log(keystreamProbDist))

    return np.argmax(candidateWeights)


def basicPTRecoveryAttack(encryptionByteFreqs, keystreamProbDist):
    messageLen = encryptionByteFreqs.shape[0]
    decrypted = bytearray([singleByteBiasEstimateByte(encryptionByteFreqs[cipherPos],
                                                      keystreamProbDist[cipherPos])
                           for cipherPos in range(messageLen)])
    print('Estimated decryption:', decrypted)


def main():
    password = '123456'

    # pwCounts, totalPasswords = getPasswordCounts('rockyou-withcount.txt')
    # pwProbabilities = computePasswordProbabilities(pwCounts, totalPasswords)
    #
    # count = 0
    # print('Probability of 123456:', pwProbabilities['123456'])
    # print('Probability of 12345:', pwProbabilities['12345'])
    # print('Probability of password:', pwProbabilities['password'])
    # for password in pwProbabilities:
    #     count += 1
    #     if count > 10:
    #         break
    #     print('Probability of {}: {}'.format(password, pwProbabilities[password]))
    # commonPwProbs = getSortedPasswords(pwProbabilities)[:TOP_PASSWORDS]
    # mostCommonPws = [pw for (pw, probability) in commonPwProbs]
    # print('Most common pws:', mostCommonPws[:10])
    #
    # # encryptionSamples = getEncryptionSamples(mostCommonPws, 100)
    # mostCommonPwSamples, password = generateEncryptionDist(mostCommonPws[0], 2 ** 22)
    #
    # # graphByteProbabilities(password, mostCommonPwSamples)
    byteProbs = loadByteProbabilities(password)
    print('ByteProbs:', byteProbs[1])
    # graphByteProbabilitiesByBytePos(password, byteProbs)
    # graphByteFreqsByByteValue(password, byteProbs)
    # graphByteEntropyByByteValue(password, byteProbs)
    # graphEntropyByBytePosition(password, byteProbs)

    keystreamFreqs = generateKeystreamDist(password, 2 ** 20, 5)
    # graphKeystreamDistByBytePos(keystreamFreqs, 1)
    # graphKeystreamDistByByteValue(keystreamFreqs, 0)
    keystreamProbDist = getKeystreamProbabilityDist(keystreamFreqs)
    basicPTRecoveryAttack(byteProbs, keystreamProbDist)


if __name__ == '__main__':
    main()

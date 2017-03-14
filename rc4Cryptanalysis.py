import pickle
import os.path
import numpy as np
from Crypto.Cipher import ARC4
from Crypto import Random
from math import log
import matplotlib.pyplot as plt

KEY_SIZE = 16
rand = Random.new()
TOP_PASSWORDS = 100000
encryptionSamplePickle = 'encryptedPws.p'
SINGLE_PW_PICKLE = 'singlePw.p'
BYTE_DIST_PICKLE = 'byteDist.p'
KEYSTREAM_DIST_PICKLE = 'keystream.p'
TLS_FINISH = 'TLS Finished: password='


def x_or(byteArrOne, byteArrTwo):
    # strOneBytes = bytearray(bytes(strOne))
    # strTwoBytes = bytearray(bytes(strTwo))

    return bytearray(
        [byteOne ^ byteTwo for byteOne, byteTwo
         in zip(byteArrOne, byteArrTwo)])


def generateKeystreamDist(password, count, keyReuses, forceReload=False):
    if not forceReload and os.path.isfile(KEYSTREAM_DIST_PICKLE):
        keystreamDist = pickle.load(open(KEYSTREAM_DIST_PICKLE, 'rb'))
    else:
        byteSize = 256
        message = TLS_FINISH + password
        messageLen = len(message)
        messageBytes = bytearray(bytes(message))
        step = int(count * keyReuses / 10)
        curStep = step
        keystreamDist = np.zeros(shape=(messageLen, byteSize), dtype=int)

        for keyCount in range(count):
            key = rand.read(KEY_SIZE)
            rc4 = ARC4.new(key)

            for keyReuse in range(keyReuses):
                if keyCount == curStep:
                    print('{}% done'.format(100 * curStep / count))
                    curStep += step
                encryptedMsg = bytearray(bytes(rc4.encrypt(message)))
                keystream = x_or(encryptedMsg, messageBytes)
                for position, byte in enumerate(keystream):
                    keystreamDist[position][byte] += 1

                # encryptedPws[i] = bytearray(bytes(rc4.encrypt(message)))

        pickle.dump(keystreamDist, open(KEYSTREAM_DIST_PICKLE, 'wb'))
    return keystreamDist


def singlePasswordEncrypt(password, count, forceReload=False):
    if not forceReload and os.path.isfile(SINGLE_PW_PICKLE):
        pwEncryptions = pickle.load(open(SINGLE_PW_PICKLE, 'rb'))
        # newPwEncryptions = np.ndarray(shape=(count), dtype=object)
        # for index, encryption in enumerate(pwEncryptions):
        #     newPwEncryptions[index] = bytearray(bytes(encryption))
        # print(newPwEncryptions[:5])
        # pickle.dump((newPwEncryptions, password), open(SINGLE_PW_PICKLE + '_new', 'wb'))
    else:
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
            # print('Encryption len:', len(encryptedPws[i]), encryptedPws[i])
        pwEncryptions = (encryptedPws, password)
        pickle.dump(pwEncryptions, open(SINGLE_PW_PICKLE, 'wb'))

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
    if not forceReload and os.path.isfile(encryptionSamplePickle):
        print('loading pickled file')
        matrix = pickle.load(open(encryptionSamplePickle, 'rb'))
    else:
        # samples = [encryptPassword(pw, encryptionCount) for pw in passwords]
        samples = []
        for pw in passwords:
            samples.extend(encryptPassword(pw, encryptionCount))
        # print(samples)
        matrix = np.asmatrix(samples)
        pickle.dump(matrix, open(encryptionSamplePickle, 'wb'))
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
    byteSize = 256
    numBytes = len(TLS_FINISH + password)

    if os.path.isfile(BYTE_DIST_PICKLE):
        frequencies = pickle.load(open(BYTE_DIST_PICKLE, 'rb'))
    elif pwEncryptions is not None:
        frequencies = np.zeros(shape=(numBytes, byteSize), dtype=int)

        for index, encryption in enumerate(pwEncryptions):
            # print('Encryption len:', len(encryption), encryption)
            for byteNum, byte in enumerate(encryption):
                frequencies[byteNum][int(byte)] += 1
        pickle.dump(frequencies, open(BYTE_DIST_PICKLE, 'wb'))
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

def basicPTRecoveryAttack(encryptions):
    pass



def main():
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
    # mostCommonPwSamples, password = singlePasswordEncrypt(mostCommonPws[0], 2 ** 22)
    # print('Encrypted samples:', mostCommonPwSamples[:10])

    # graphByteProbabilities(password, mostCommonPwSamples)
    # byteProbs = loadByteProbabilities('123456')
    # graphByteProbabilitiesByBytePos('123456', byteProbs)
    # graphByteFreqsByByteValue('123456', byteProbs)
    # graphByteEntropyByByteValue('123456', byteProbs)
    # graphEntropyByBytePosition('123456', byteProbs)
    keystreamDist = generateKeystreamDist('123456', 2**17, 5)
    plt.plot(keystreamDist[1, :])
    axes = plt.gca()
    axes.set_xlim([-5, 270])
    plt.show()
    print(keystreamDist[1, :])


if __name__ == '__main__':
    main()

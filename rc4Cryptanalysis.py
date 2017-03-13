import numpy as np
from Crypto.Cipher import ARC4
from Crypto import Random
from math import log

KEY_SIZE = 20
rand = Random.new()


# encrypt passwords with randomly generated key
def encryptPassword(password, count):
    key = rand.read(KEY_SIZE)
    rc4 = ARC4.new(key)
    return [[rc4.encrypt(password), password] for i in range(count)]


def getEncryptionSamples(passwords, encryptionCount):
    samples = [encryptPassword(pw, encryptionCount) for pw in passwords]
    return np.asmatrix(samples)


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


def main():
    pwCounts, totalPasswords = getPasswordCounts('rockyou-withcount.txt')
    pwProbabilities = computePasswordProbabilities(pwCounts, totalPasswords)

    count = 0
    print('Probability of 123456:', pwProbabilities['123456'])
    print('Probability of 12345:', pwProbabilities['12345'])
    print('Probability of password:', pwProbabilities['password'])
    for password in pwProbabilities:
        count += 1
        if count > 10:
            break
        print('Probability of {}: {}'.format(password, pwProbabilities[password]))
    encryptionSamples = getEncryptionSamples(pwProbabilities.keys(), 1000)
    print('Encryptions:', encryptionSamples[:5])


if __name__ == '__main__':
    main()

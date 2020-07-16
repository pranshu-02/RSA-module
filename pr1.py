#
import sys, threading
import random
import utils

sys.setrecursionlimit(10**7)
threading.stack_size(2**27)

def ConvertToInt(message_str):
  res = 0
  for i in range(len(message_str)):
    res = res * 256 + ord(message_str[i])
  return res

def ConvertToStr(n):
    res = ""
    while n > 0:
        res += chr(n % 256)
        n //= 256
    return res[::-1]

def PowMod(a, n, mod):
    if n == 0:
        return 1 % mod
    elif n == 1:
        return a % mod
    else:
        b = PowMod(a, n // 2, mod)
        b = b * b % mod
        if n % 2 == 0:
          return b
        else:
          return b * a % mod


def ExtendedEuclid(a, b):
    if b == 0:
        return (1, 0)
    (x, y) = ExtendedEuclid(b, a % b)
    k = a // b
    return (y, x - k * y)

def InvertModulo(a, n):
    (b, x) = ExtendedEuclid(a, n)
    if b < 0:
        b = (b % n + n) % n
    return b

def GCD(a, b):
  if b == 0:
    return a
  return GCD(b, a % b)


def Decrypt(ciphertext, p, q, exponent):
  d=InvertModulo(exponent,(p-1)*(q-1))
  return ConvertToStr(PowMod(ciphertext, d, p * q))

def Encrypt(message, modulo, exponent):
  return PowMod(ConvertToInt(message), exponent, modulo)

def isLowPrime(num):
  lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 
   67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 
   157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 
   251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,317, 331, 337, 347, 349, 
   353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 
   457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 
   571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 
   673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 
   797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 
   911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
  for divisor in lowPrimes:
    if num % divisor == 0 and divisor**2 <= num:
      return False
  else: return True
  
def MillerRabin(num):
  t=num-1
  divby2=0
  while t%2 == 0:
    divby2+=1
    t >>=1
  numOfRounds=20
  for i in range(numOfRounds):
    tester = random.randrange(2, num-1)
    x=pow(tester, t, num)
    if x == 1 or x == num-1:
      return True
    while t != num-1:
        x = (x * x) % num 
        t *= 2
        if x == 1:
          return False 
        if x == num-1:
          return True
    return False
   
def generateLargePrime(n):
  while True:
    num=random.randrange(2**(n-1)+1, 2**n - 1)
    if isLowPrime(num) and MillerRabin(num):
        return num
        break
    else:
      continue

def generateKeys(keySize = 1024):
  p=generateLargePrime(keySize)
  q=generateLargePrime(keySize)
  







#1 potential message
def DecipherSimple(ciphertext, modulo, exponent, potential_messages):
      if ciphertext == Encrypt(potential_messages[0], modulo, exponent):
        return potential_messages[0]
      elif ciphertext == Encrypt(potential_messages[1], modulo, exponent):
        return potential_messages[1]
      elif ciphertext == Encrypt(potential_messages[2], modulo, exponent):
        return potential_messages[2]    
      return "don't know"

#2 p or q less than 1,000,000
def DecipherSmallPrime(ciphertext, modulo, exponent):  
      for x in range(2,1000000):
        if modulo % x == 0:
          small_prime = x
          big_prime = modulo // x
          return Decrypt(ciphertext, small_prime, big_prime, exponent)
      return "don't know"

#3 |p-q| < 5000
def IntSqrt(n):
  low = 1
  high = n
  iterations = 0
  while low < high and iterations < 5000:
    iterations += 1
    mid = (low + high + 1) // 2
    if mid * mid <= n:
      low = mid
    else:
      high = mid - 1
  return low


def DecipherSmallDiff(ciphertext, modulo, exponent):
  for x in range(IntSqrt(modulo)-5000,IntSqrt(modulo)+1):
    if modulo % x ==0:
      small_prime = x
      big_prime = modulo // small_prime
      return Decrypt(ciphertext, small_prime, big_prime, exponent)

#4 2 cipher have one common divisor
def DecipherCommonDivisor(first_ciphertext, first_modulo, first_exponent, second_ciphertext, second_modulo, second_exponent):
  # Fix this implementation to correctly decipher both messages in case
  # first_modulo and second_modulo share a prime factor, and return
  # a pair (first_message, second_message). The implementation below won't work
  # if the common_prime is bigger than 1000000.
  g= GCD(first_modulo,second_modulo)
  if g!=1:
    return (Decrypt(first_ciphertext, g, first_modulo//g, first_exponent), Decrypt(second_ciphertext, g, second_modulo//g, second_exponent))
  return ("unknown message 1", "unknown message 2")

#5 2 have same exponent

def DecipherCommonDivisor(first_ciphertext, first_modulo, first_exponent, second_ciphertext, second_modulo, second_exponent):
  # Fix this implementation to correctly decipher both messages in case
  # first_modulo and second_modulo share a prime factor, and return
  # a pair (first_message, second_message). The implementation below won't work
  # if the common_prime is bigger than 1000000.
  g= GCD(first_modulo,second_modulo)
  if g!=1:
    return (Decrypt(first_ciphertext, g, first_modulo//g, first_exponent), Decrypt(second_ciphertext, g, second_modulo//g, second_exponent))
  return ("unknown message 1", "unknown message 2")

#6 

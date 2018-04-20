import random
import socket
import hashlib
import ctypes
import struct


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modular_math(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
###### end resource
def ppc(x):  #From Dr. Ramkumar's formula in his notes
   # print("In PPC")
    count = 0
    n = 40
    while count < n:
        a = random.randint(1, 99999)
        #replace with pow
        moda = pow(a, x, x)
        #expa = a ** x
        #moda = expa % x
        if moda == a:
            count += 1
        else:
            break
       # print(count)
    if count == n:
        return True
    else:
        return False

def pick_prime():           #From Dr. Ramkumars formula
  #  print("In Pick Prime")
    a = 40 # number of bits
    p = random.getrandbits(a)   #found random function here https://stackoverflow.com/questions/16496733/how-to-generate-a-number-of-n-bit-in-length-using-python
    if p % 2 == 0:
        p = p + 1
    while ppc(p) == False:
        p += 2
       # print(p)

    return p

def gcd(e,phi):  # resource https://stackoverflow.com/questions/11175131/code-for-greatest-common-divisor-in-python
  #  print("Enter GCD")
    while phi != 0:
        (e,phi) = (phi, e % phi)
    return e

def decrypt_it(cipher_text, n, d):
    #plain_text = None
    #for character in cipher_text:d
        #replace with pow
    #    char_mod = pow(character, d, n)
        #char_exponent = character ** d
        #char_mod = char_exponent % n
    #    plain_text += chr(char_mod)

    plain_text = [chr(pow(int(character), d, n)) for character in cipher_text]
    return "".join(plain_text)
    #return plain_text

def gen_key_pair():  # following Dr. Ramkumar's notes
  #  print("in gen_key_pair")
    #pick to large primes
    p = pick_prime()
    q = pick_prime()

    n = p*q
    phi = (p-1)*(q-1)

    e = random.randrange(1, phi)  #use randrange to return type

    gcd1 = gcd(e, phi)
  #  print("GCD: ", gcd1)
    while gcd1 != 1:  # loops until e is such taht (e,phi(n)) = 1
        e = random.randrange(1, phi)  #go to another value
        gcd1 = gcd(e, phi)

    #multiplicative inverse.
    d = modular_math(e, phi)
#    print("return from math")

    return p, q, n, e, d  # returning private key,

def tea_decrypt(key, vv1):
    delta = 0x9e3779b9
    sumkeeper = ctypes.c_uint32(3337565984)
    #vv1 = ctypes.c_uint32(vv1)
    #vv2 = ctypes.c_uint32(vv2)
    vv1, vv2 = map(ctypes.c_uint32, struct.unpack('!LL', vv1[0:8]))
    k0 = ctypes.c_uint32(key[0])
    k1 = ctypes.c_uint32(key[1])
    k2 = ctypes.c_uint32(key[2])
    k3 = ctypes.c_uint32(key[3])
    for i in range(0,32):
        vv2.value -= ((vv1.value << 4) + k2.value) ^ (vv1.value + sumkeeper.value) ^ ((vv1.value >> 5) + k3.value)
        vv1.value -= ((vv2.value << 4) + k0.value) ^ (vv2.value + sumkeeper.value) ^ ((vv2.value >> 5) + k1.value)
        sumkeeper.value -= delta
    v3 = struct.pack('!LL', vv1.value, vv2.value)

    return v3


def rsa_keygen():
    pass
def key_decrypt():
    pass

def main():  #Runs Server
    #open socket to listen for client

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    try:
        s.bind((host, 55555))
    except socket.error as msg:
        import sys
        print("Socket Bind Failed.  Error: " + str(sys.exc_info()))
        sys.exit()
    print("Server Started, Listening for Client")
    s.listen(5)
   # connection, address = s.accept()

   # while True:
   #     connection, address = s.accept()
   #     isclient = connection.recv(4096)
   #     isclient_string = isclient.decode('utf8')
    connection, address = s.accept()
    isclient = connection.recv(4096)
    isclient_string = isclient.decode('utf8')

    #print(isclient_string)

    if isclient_string == "gibPW":
        #Generate RSA PKI
        p, q, n, e, d = gen_key_pair()  # p() q() n(p*q), e(Private), d(public)
    print("Client Identified, generating RSA Key")
    nE = str(n).encode('utf8')
    print("n: ", n)
    print("e: ", e)
    #while True:
    connection.send(nE)
        #while True:
    dE = str(e).encode('utf8')
    #print(e)
    connection.send(dE)
    print("Sending n and e to client")

    rsa_recv = connection.recv(4096)
    rsa_recv_string = rsa_recv.decode('utf8').strip('[] ').split(',') #strip("]").strip("[").split() #strip("'").strip("cmd").strip(",").split()
    #rsa_recv_string = rsa_recv.decode('utf8')
    #print(rsa_recv_string[0])
   # print("type: ", type(rsa_recv_string[0]))
   # iv = rsa_recv_string[-10:]
    #print(rsa_recv)
    print("Enc_KEY: ", rsa_recv_string)
    tea_key = decrypt_it(rsa_recv_string, n, d)
    split = tea_key.split('x', 1)
    print(split)
    iv = int(split[1])
    tea_key = int(split[0])
    print("TEA_KEY", tea_key)
    key = tea_key & 0xffffffffffffffffffffffffffffffff
    print("KEY: ", key)
    print("IV: ", iv)


    k1 = key & 0xffffffff
    k2 = (key >> 32) & 0xffffffff
    k3 = (key >> 64) & 0xffffffff
    k4 = (key >> 96) & 0xffffffff

    key_parts = [k1, k2, k3, k4]

   # print(tea_key)

   # print(tea_key)



   # file3 = open("ENC_CSE4383.html", "rb")
    file4 = open("DEC2_CSE4383.html", "wb")

   # v3 = 0x0000000000000000
    #v4 = 0x00000000

    #vv1 = 0xffffffff
    #vv2 = 0xffffffff

    vv1 = iv
   # vv2 = iv
    flag = 0

    print("Beginning Receive of Encrypted File")

    #with open("CSE4383.html", "rb") as file1:
    try:
        while True:
            #v1 = int.from_bytes(file3.read(4), byteorder='big')
            #v2 = int.from_bytes(file3.read(4), byteorder='big')
            v1_data = connection.recv(4096)
            connection.send(v1_data)

            #v1_size = int(connection.recv(4096).decode('utf8'))
            #connection.send("Happy".encode('utf8'))

           # v2_data = connection.recv(4096)
           # connection.send(v2_data)

            #v2_size = int(connection.recv(4096).decode('utf8'))
            #connection.send("Happy".encode('utf8'))
          #  print(v1_size)
          #  print(v2_size)

            v1_string = v1_data.decode("utf8")
            #v2_string = v2_data.decode("utf8")

            #print(v1_string)
            #print(v2_string)
            #try:
            #    v1 = int(v1_string)
                #v2 = int(v2_string)
            #except:
            #    break

            #print(v1)
            #if not v1:
            #    flag = 1
            #if not v2:
            #    flag = 1
            pad = v1_string[-1:]
            v1_holder = v1_string[:-1]
            v1 = int(v1_holder)
            v1 = v1 & 0xffffffffffffffff
            v1_byte = int.to_bytes(v1, 8, byteorder='big')
            #v2 = v2 & 0xffffffff

            v3_byte = tea_decrypt(key_parts, v1_byte)
            v3 = int.from_bytes(v3_byte, byteorder='big')

            vv3 = vv1 ^ v3
           # vv4 = vv2 ^ v4

            vv1 = v1
            #vv2 = v2

           # print(v3)
            #print(v4)
            numbytes1 = 8
            if int(pad) != 0:
                numbytes1 = numbytes1 - int(pad)
            #numbytes2 = 4
            #if v1_size < 4:
            #    numbytes1 = v1_size
            file4.write(int.to_bytes(vv3, numbytes1, byteorder='big'))
            #if v2_size < 4:
            #    numbytes2 = v2_size
            #file4.write(int.to_bytes(vv4, numbytes2, byteorder='big'))
            #numbytes1 = 4
            #numbytes2 = 4

            if flag == 1:
                break
    except:

    #file3.close()
        file4.close()

    print("Receive and Decryption Completed")


    #while True:
    #    enc_file = connection.recv(4096)
    #    file3.write(enc_file)


main()

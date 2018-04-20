import random
import socket
import hashlib
import ctypes
import sys
import struct


def encrypt_it(plain_text, n, e):  #was h aving issues getting data into the cipher and out of
    #from here this line fixed by input https://gist.github.com/JonCooperWorks/5314103
    #cipher = [(ord(char) ** key) % n for char in plaintext]
    #cipher_text = ""
    #for character in plain_text:
    #    convert_char = ord(character)
    #    #replace with pow
    #    p_mod = pow(convert_char, e, n)
    #    #p_exponent = convert_char ** e
    #    #p_mod = p_exponent % n
    #    cipher_text += (p_mod)

    cipher_text = [pow(ord(character), e, n) for character in plain_text]
    return cipher_text


def tea_encrypt(key, vv1):
    delta = 0x9e3779b9
    sumkeeper = ctypes.c_uint32(0)
   # i = ctypes.c_uint32()
   # vv1 = ctypes.c_uint32(vv1)
   # vv2 = ctypes.c_uint32(vv2)
    vv1, vv2 = map(ctypes.c_uint32, struct.unpack('!LL', vv1[0:8]))
    k0 = ctypes.c_uint32(key[0])
    k1 = ctypes.c_uint32(key[1])
    k2 = ctypes.c_uint32(key[2])
    k3 = ctypes.c_uint32(key[3])
   #  print("vv1: ", vv1)
   #  print("vv2: ", vv2)
   #  print("k0: ", k0)
   #  print("k1: ", k1)
   #  print("k2: ", k2)
   #  print("k3: ", k3)

    for i in range(0, 32):
        sumkeeper.value += delta
        vv1.value += ((vv2.value << 4) + k0.value) ^ (vv2.value + sumkeeper.value) ^ ((vv2.value >> 5) + k1.value)
        vv2.value += ((vv1.value << 4) + k2.value) ^ (vv1.value + sumkeeper.value) ^ ((vv1.value >> 5) + k3.value)

    v3 = struct.pack('!LL', vv1.value, vv2.value)

    return v3, sumkeeper.value

def tea_decrypt(key, vv1):
    delta = 0x9e3779b9
    sumkeeper = ctypes.c_uint32(3337565984)
   # vv1 = ctypes.c_uint32(vv1)
   # vv2 = ctypes.c_uint32(vv2)
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


def key_encrypt():
    pass

def main():  #runs the client code and calls correct functions
    #open socket and connect to server
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    c.connect((host, 55555))
    print("Client Started, sending Initial Response to Server")
    #send request to server for pw
    c.send("gibPW".encode("utf8"))

    print("Received n and e from server")
    n = c.recv(4096)
    n_string = n.decode('utf8')
    intn = int(n_string)
    print("n: ", intn)
    #print(intn)

    e = c.recv(4096)
    e_string = e.decode('utf8')
    inte = int(e_string)
    print("e: ", inte)

    print("Generating Key and IV")

    #Generate 128 Bit Random Number
    key = random.getrandbits(128)

    ##print(key)
   # hexkey = hex(key)
    key = key & 0xffffffffffffffffffffffffffffffff
    print("KEY: ", key)
    iv = random.getrandbits(64)
    iv = iv & 0xffffffffffffffff
    print("IV:", iv)
    iv_string = str(iv)
    ##print(key)
    key_string = str(key)
    #print("key_string", key_string)
    key_string += "x"
    key_string += iv_string
    #print("key_iv", key_string)
    rsa_key = encrypt_it(key_string, intn, inte)
    print("Encrypting Key and IV")
    print("Encrypted Key with IV: ", rsa_key)
    print("Sending Encrypted Key and IV")
   # print("keyType: ", type(rsa_key))
    #print("n: ", intn)
    #print("e: ", inte)

   #print(key)
   # print(rsa_key)

    c.send(str(rsa_key).encode("utf8"))
    #c.send(rsa_key)

    hexkey = hex(key)

    #key_parts = struct.unpack('4B', hexkey)
    k1 = key & 0xffffffff
    k2 = (key >> 32) & 0xffffffff
    k3 = (key >> 64) & 0xffffffff
    k4 = (key >> 96) & 0xffffffff

    key_parts = [k1, k2, k3, k4]
    print(key_parts)
  #  print(key_parts)

    file1 = open("CSE4383.html", "rb")
    file2 = open("ENC_CSE4383.html", "wb")

    #v3 = ctypes.c_uint32(0x00000000)
    #v4 = ctypes.c_uint32(0x00000000)
    #iv = random.getrandbits(32)
    #iv = iv & 0xffffffff
    #ivhex = hex(iv)
    #print("ivLen", len(ivhex))
    #print("IV", iv)
    #print("IVhex", ivhex)
    #ivint = int(ivhex, 16)
    #print("IVint", ivint)

    v3 = iv
   # v4 = iv

    flag = 0
    print("Beginning Encryption and Send...")
    #with open("CSE4383.html", "rb") as file1:
    while True:
        #v1temp = int.from_bytes(file1.read(4), byteorder='big')
        #v2temp = int.from_bytes(file1.read(4), byteorder='big')
        v1temp = file1.read(8)
        #v2temp = file1.read(4)
        v1_len = len(v1temp)
        pad = 8 - v1_len
       # print(v1_len)
        #v2_len = len(v2temp)
       # if sys.getsizeof(v1temp) < 4:
       #     v1temp = v1temp << (4 - sys.getsizeof(v1temp))
       # if sys.getsizeof(v2temp) < 4:
       #     v2temp = v2temp << (4 - sys.getsizeof(v2temp))

        v1 = int.from_bytes(v1temp, byteorder='big')
       # v2 = int.from_bytes(v2temp, byteorder='big')

       # print("vv1: ", len(v1))
       # print("vv2: ", len(v2))

        # if sys.getsizeof(v1) < 18:
        #     v1 = v1 << 4*(18-sys.getsizeof(v1))
        # if sys.getsizeof(v2) < 18:
        #     v2 = v2 << 4*(18-sys.getsizeof(v2))


      #  print(sys.getsizeof(v1))

        #print(v1)
        if len(v1temp) < 8:
            flag = 1
       # if len(v2temp) < 4:
       #     flag = 1
        v1 = v1 & 0xffffffffffffffff
        #v2 = v2 & 0xffffffff

        v1 = v1 ^ v3
        #v2 = v2 ^ v4
        v1_byte = int.to_bytes(v1, 8, byteorder='big')
        v3_byte, sum = tea_encrypt(key_parts, v1_byte)
        #print(sum)
        #print("v3: ", v3)
        #print("v4: ", v4)
        #v3_string = str(v3)
        #v4_string = str(v4)
        #v3_string += v4_string
      #  v3v4_string = v3_string + v4_string

      #  print("v3: ", len(v3_string))
      #  print("v4: ", len(v4_string))
        #print("v3v4: ", v3v4_string)
        #print("lenV3V4: ", len(v3v4_string))
      #  v3v4 = int.to_bytes(int(v3v4_string), 8, byteorder='big')
        #v3v4 += int.to_bytes(v4, 4, byteorder='big')
        #print("v3v4: ", v3v4)
       # print(int.to_bytes(v3, 4, byteorder='big'))
       # print(int.to_bytes(v4, 4, byteorder='big'))

       # print(len(v3v4))
        #### v3_bytes = int.to_bytes(v3, 8, byteorder='big')
        #v4_bytes = int.to_bytes(v4, 4, byteorder='big')
       # print('V3ByteLen: ', len(v3_bytes))
       # print('V4ByteLen: ', len(v4_bytes))
        ##file2.write(int.to_bytes(v3, 8, byteorder='big'))
        #file2.write(v3, 8, byteorder='big')
        #file2.write(int.to_bytes(v4, 4, byteorder='big'))
        #print(v3)
       # print(v4)
        #v3_len = len(v3)
        #v4_len = len(v4)
       # print(v3_len, " ", v4_len)
        v3 = int.from_bytes(v3_byte, byteorder='big')
        v3_string = str(v3) + str(pad)
        #print("debug")
        file2.write(v3_byte)
        c.send(v3_string.encode("utf8"))
        c.recv(4096)
        #print("debug2")
        #c.send(str(len(v1temp)).encode('utf8'))
        #c.recv(1024)

      #  c.send(str(v4).encode("utf8"))
      #  c.recv(4096)

        #c.send(str(len(v2temp)).encode('utf8'))
        #c.recv(1024)
       # print("flag: ", flag)
        if flag == 1:
            break

   # print(sum)
    file1.close()
    file2.close()
    print("Encrypted File Has Been Sent")

    # file3 = open("ENC_CSE4383.html", "rb")
    # file4 = open("DEC_CSE4383.html", "wb")
    #
    # v3 = 0x00000000
    # v4 = 0x00000000
    #
    # vv1 = 0x00000000
    # vv2 = 0x00000000
    #
    # flag = 0
    #
    # #with open("CSE4383.html", "rb") as file1:
    # while True:
    #     v1 = int.from_bytes(file3.read(4), byteorder='big')
    #     v2 = int.from_bytes(file3.read(4), byteorder='big')
    #
    #     #print(v1)
    #     if not v1:
    #         flag = 1
    #     if not v2:
    #         flag = 1
    #     v1 = v1 & 0xffffffff
    #     v2 = v2 & 0xffffffff
    #
    #     v3, v4 = tea_decrypt(key_parts, v1, v2)
    #
    #     vv3 = vv1 ^ v3
    #     vv4 = vv2 ^ v4
    #
    #     vv1 = v1
    #     vv2 = v2
    #
    #    # print(v3)
    #     #print(v4)
    #
    #     file4.write(int.to_bytes(vv3, 4, byteorder='big'))
    #     file4.write(int.to_bytes(vv4, 4, byteorder='big'))
    #
    #     if flag == 1:
    #         break
    #
    # file3.close()
    # file4.close()



   # c.send(str(v3.value))
   # c.send(str(v4.value))



   # while True:
    # wait for response from server RSA PKI


   # RSA_PKI = c.recv(4096)
   # RSA_PKI_String = RSA_PKI.decode("utf8")


main()



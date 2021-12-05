##MINI-AES IMPLEMENTATION - DECRYPTION - INTERACTIVE PYTHON FILE
##AUTHOR: HISHAN PARRY
##EMAIL: HMRP1R17@SOTON.AC.UK
##ID: 28313283
##DATE: 04/12/2021

k = 0b1100001111110000 #16-bit key

irdc_poly = [0,0,1,0,0,1,1] #x^4+x+1
const_mat = [[0,0,1,1], [0,0,1,0],[0,0,1,0],[0,0,1,1]]
r_con_1 = [0,0,0,1]#round 1 const for key schedule
r_con_2 = [0,0,1,0]#round 2 const for key schedule

def get2x2NibbleMatrix(a):
#where a is a 16-bit plaintext/ key
#returns 2D nibble matrix list with 4 elements a0, a1, a2, a3 as int
    nibbleMat = []
    tempMat = []
    a = "{0:b}".format(a)
    for ind, bit in enumerate(a):
        tempMat.append(int(bit))
        if ((ind+1) % 4 == 0):
            nibbleMat.append(tempMat)
            tempMat = []
    return nibbleMat 

def nibbleSub(a):
##NIBBLE SUB TABLE CHANGED TO INVERSE FOR DECRYPTION
##substitution lookup table for nibbles in mini-AES
    if a  == [0,0,0,0]:
        a = [1,1,1,0]
    elif a  == [0,0,0,1]:
        a = [0,0,1,1]
    elif a  == [0,0,1,0]:
        a = [0,1,0,0]
    elif a  == [0,0,1,1]:
        a = [1,0,0,0]
    elif a  == [0,1,0,0]:
        a = [0,0,0,1]
    elif a  == [0,1,0,1]:
        a = [1,1,0,0]
    elif a  == [0,1,1,0]:
        a = [1,0,1,0]
    elif a  == [0,1,1,1]:
        a = [1,1,1,1]
    elif a  == [1,0,0,0]:
        a = [0,1,1,1]
    elif a  == [1,0,0,1]:
        a = [1,1,0,1]
    elif a  == [1,0,1,0]:
        a = [1,0,0,1]
    elif a  == [1,0,1,1]:
        a = [0,1,1,0]
    elif a  == [1,1,0,0]:
        a = [1,0,1,1]
    elif a  == [1,1,0,1]:
        a = [0,0,1,0]
    elif a  == [1,1,1,0]:
        a = [0,0,0,0]
    elif a  == [1,1,1,1]:
        a = [0,1,0,1]
    else:
        print('Error in nibbleSub lookup table!') 
    return a
    
def nibbleSub_ENC_TABLE(a):
##NIBBLE SUB TABLE FROM ORIGINAL ENCRYPTION ALGORITHM
##substitution lookup table for nibbles in mini-AES
    if a  == [0,0,0,0]:
        a = [1,1,1,0]
    elif a  == [0,0,0,1]:
        a = [0,1,0,0]
    elif a  == [0,0,1,0]:
        a = [1,1,0,1]
    elif a  == [0,0,1,1]:
        a = [0,0,0,1]
    elif a  == [0,1,0,0]:
        a = [0,0,1,0]
    elif a  == [0,1,0,1]:
        a = [1,1,1,1]
    elif a  == [0,1,1,0]:
        a = [1,0,1,1]
    elif a  == [0,1,1,1]:
        a = [1,0,0,0]
    elif a  == [1,0,0,0]:
        a = [0,0,1,1]
    elif a  == [1,0,0,1]:
        a = [1,0,1,0]
    elif a  == [1,0,1,0]:
        a = [0,1,1,0]
    elif a  == [1,0,1,1]:
        a = [1,1,0,0]
    elif a  == [1,1,0,0]:
        a = [0,1,0,1]
    elif a  == [1,1,0,1]:
        a = [1,0,0,1]
    elif a  == [1,1,1,0]:
        a = [0,0,0,0]
    elif a  == [1,1,1,1]:
        a = [0,1,1,1]
    else:
        print('Error in nibbleSub lookup table!') 
    return a

def sub2x2(a):
#where a is a 2D nibble matrix list with 4 elements a0, a1, a2, a3
#returns substituted 2D matrix of nibbles b0, b1, b2, b3 using lookup table
    for ind, nibble in enumerate(a):
        a[ind] = nibbleSub(a[ind])  
    return a

def shiftRow(a):
##where a is a 2D nibble matrix list with 4 elements a0, a1, a2, a3
##returns 2D nibble matrix shifted so output is a0, a3, a2, a1
    shiftOrder = [0, 3, 2, 1]
    a = [a[nibble] for nibble in shiftOrder]
    return a

def rotateList(a, x):
##returns an input list a shifted x number of times to the left
    return a[x:] + a[:x]

def nibbleXOR(a, b):
###where a and b are a list of 1 nibble each
##returns nibble list with XOR operation performed c0, c1, c2, c3
##simple XOR function implemented on list of int bits
##also works for lists bigger than a nibble - used in nibbleMult function
    c = []
    for bit_i in range(len(a)):
        x = a[bit_i] ^ b[bit_i]
        c.append(x)
    return c

def nibbleMult(a, b):
###where a and b are a list of 1 nibble each
##returns nibble list with Galois field Multiplication performed for output c0, c1, c2, c3, c4
    c = [0,0,0,0,0,0,0]
    
    #multiplication part
    for i in range(len(a)):
        for j in range(len(b)):
            c[i+j] ^=  a[i]*b[j]
    #print (c)
    
    #division part
    #print (c) -- COME BACK TO THIS WHILE STATEMENT IF SOMETHING GOES WRONG IN ENCRYPTION
    while(1 in c and c.index(1) < 3):#loop until power < x^4
        shiftNum = 2 - c.index(1) #find number of times to shift divisor left based on power
        x = rotateList(irdc_poly, shiftNum) #shift irdc_poly by shiftNum to left
        c = nibbleXOR(c, x)#XOR function
    
    return (c[3:])##returns last 4 bits of c - first 3 powers don't exist after mult

def mixColumn(a):
##where a is a 2D nibble matrix list with 4 elements a0, a1, a2, a3
##where const_mat is the chosen constant matrix for the mix column operation
##returns an output list b where the columns are mixed by multiplying with const_mat
    b = [[],[],[],[]]
    b[0] = nibbleXOR(nibbleMult(const_mat[0], a[0]), nibbleMult(const_mat[1], a[1]))
    b[1] = nibbleXOR(nibbleMult(const_mat[2], a[0]), nibbleMult(const_mat[3], a[1]))
    b[2] = nibbleXOR(nibbleMult(const_mat[0], a[2]), nibbleMult(const_mat[1], a[3]))
    b[3] = nibbleXOR(nibbleMult(const_mat[2], a[2]), nibbleMult(const_mat[3], a[3]))
    return b

def get2x2NibbleMatFromString(a):
##gets a 2x2 nibble Mat from a string of binary 1's and 0's
    nibbleMat = []
    tempMat = []
    for ind, bit in enumerate(a):
        tempMat.append(int(bit))
        if ((ind+1) % 4 == 0):
            nibbleMat.append(tempMat)
            tempMat = []
    return nibbleMat
    
def getBinStringFromBinMat(a):
##gets a binary string from a 2x2 int binary matrix
    bin_string = ""
    for i in a:
        for j in i:
            bin_string += str(j)
    return bin_string

def keyAddition(a, round):
##NIBBLE SUB OPERATION IN KEY ADDITION USES ORIGINAL S-BOX TABLE FROM ENCRYPTION
##performs operation (a XOR k[round])
##XOR of a with key specific to that round
##returns result of this operation as 2D nibble list of int b
    keys = [[],[],[]]
    keys[0] = get2x2NibbleMatrix(k)
    #print(nibbleSub(keys[0][3]))
    keys[1].append(nibbleXOR(nibbleXOR(keys[0][0], nibbleSub_ENC_TABLE(keys[0][3])), r_con_1))
    keys[1].append(nibbleXOR(keys[0][1], keys[1][0]))
    keys[1].append(nibbleXOR(keys[0][2], keys[1][1]))
    keys[1].append(nibbleXOR(keys[0][3], keys[1][2]))
    
    keys[2].append(nibbleXOR(nibbleXOR(keys[1][0], nibbleSub_ENC_TABLE(keys[1][3])), r_con_2))
    keys[2].append(nibbleXOR(keys[1][1], keys[2][0]))
    keys[2].append(nibbleXOR(keys[1][2], keys[2][1]))
    keys[2].append(nibbleXOR(keys[1][3], keys[2][2]))
    
    #print(keys)
    
    for ind, nibble in enumerate(a):
        a[ind]  = nibbleXOR(a[ind], keys[round][ind])
    
    return a
    
def getASCIIStringFromBinString(binString):
##Converts a string of binary integers to a string of 8-bit ASCII characters
    #print("-------------------------------------------")
    stringASCII = ""
    for bitsind in range(0, len(binString), 8):
        ASCII = int(binString[bitsind:bitsind+8], 2)
        #print (binString[bitsind:bitsind+8])
        #print (ASCII)
        ASCII = chr(ASCII)
        #print(ASCII)
        stringASCII += ASCII
    #print("-------------------------------------------")
    return stringASCII

def decryptAES(encrypted_message_bin):
##uses user-defined functions to implement AES encryption with global variables
    #a = get2x2NibbleMatrix(p)
    
    decryptedBin = ""
    
    '''
    #NOT NEEDED FOR DECRYPTION PART - WE TAKE IN A BINARY STRING AS INPUT
    text_bin = [bin(ord(i))[2:] for i in plaintext]
    text_bin = ["0"*(8-len(i))+i for i in text_bin]
    if (len(text_bin) % 2 != 0):
        text_bin.append('00000000')
    bin_to_encrypt = ""
    for bin_num in text_bin:
        bin_to_encrypt += bin_num
    '''
    
    for bitsind in range(0, len(encrypted_message_bin), 16):
        x = get2x2NibbleMatFromString(encrypted_message_bin[bitsind:bitsind+16])        
        
        #--2 in reverse
        h = keyAddition(x, 2)
        #no mix column
        g = shiftRow(h)
        f = sub2x2(g)
        
        #--1 in reverse
        e = keyAddition(f, 1)
        d = mixColumn(e)
        c = shiftRow(d)
        b = sub2x2(c)
        
        #--0
        a = keyAddition(b, 0)
        
        decryptedBin += getBinStringFromBinMat(a)
    
    return decryptedBin

print()
print ("Please enter the Encrypted Plaintext Binary: ")
encryptedBin = input()
print()

print("-----------------------------------")
decryptedBin = decryptAES(encryptedBin)
print("Decrypted Message Binary: " + decryptedBin)
print()
print("Decrypted Message String: " + getASCIIStringFromBinString(decryptedBin))
print("-----------------------------------")









import math
import time
import random
import sympy
import warnings
from random import randint, seed
#ATABERK KARAMAN --- 28945 --- BATUHAN BOZTEPE --- 28960 --- CS 411_507 TERM PROJECT PHASE I ---#

import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
import hashlib
import hmac

API_URL = 'http://10.92.55.4:5000'

#stuID = 28945
stuID = 28960
#Server's Identitiy public key
IKey_Ser = 0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d, 0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093 # Use the values in the project description document to form the server's IK as a point on the EC. Note that the values should be in decimal.

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
        f.close()

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())
#Creating an eliptic curve 
E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b

stuIDAA = 26045
#-----------------IDENTITY KEY----------------------
#priv_k = randint(1, n-1)                      # //to create private key for IK
priv_k = 77130745935483247797972214598654445086751283460063310301073098601760064821023

public_k = priv_k * P                   #to create a public key for IK by generator P
print(priv_k)

#SIGNATURE GENERATION 

#k = randint(1, n-1) 
#k = 56906684785360897305379433347851221581939051139586519083294575687401582943363

k = 1748178
R = k*P
r = R.x % n
h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+stuIDAA.to_bytes((stuIDAA.bit_length()+7)//8, byteorder='big')).digest(), byteorder='big')%n
s = (priv_k *h + k) % n

print(h)
print(s)

h = 107113132909164862402153392981701239864481490775704809400284108024374036667855
s = 57139322410353434303360635805986030336717125563198459475397056574855802086106

"""
#IKRegReq(h,s,public_k.x,public_k.y) #//register request was approved via email, so we don't need to run this again

code = 858354   #from the email we recieved

#IKRegVerify(code) #//verified

#-----------------------Signed Pre-Key----------------------------------------
#creating eliptic curve
priv_k = 67662923314104435282664626284941289777438366070583458872054023206169890589609
SPK_E = Curve.get_curve('secp256k1')
SPK_n = SPK_E.order
SPK_p = SPK_E.field
SPK_P = SPK_E.generator

#saving the keys
#spk_priv = randint(1,SPK_n - 1)            #  // the method for getting the signed pre-key private
#print(spk_priv)
spk_priv = 700008819350196531834217055901683779527505439099539973538053286263043557223
spk_pub = spk_priv * SPK_P  #generating signed pre-key public

#SIGNATURE GENERATION FOR SPK
#spk_k = randint(1, SPK_n-2)            # // the method for getting the rand variable k
#print(spk_k)
spk_k = 114362635049111610895394345457413935653222623339341356807865790405945018141943
spk_R = spk_k * SPK_P
spk_r = spk_R.x % SPK_n
spk_h = int(hashlib.sha3_256(spk_r.to_bytes(32, 'big') + spk_pub.x.to_bytes(32, 'big') + spk_pub.y.to_bytes(32, 'big')).hexdigest(), 16) % SPK_n 
spk_s = (spk_k + (priv_k * spk_h)) % SPK_n

#getting the servers SPK coordinates and signature
spk_public_x, spk_public_y, spkH, spkS = SPKReg(spk_h, spk_s, spk_pub.x, spk_pub.y)


#----------------KHMAC ------------------

#creating a point of the servers SPK
spk_server_public = Point(spk_public_x, spk_public_y, SPK_E)

#generating hmac key
t = spk_priv * spk_server_public
string1 = b'CuriosityIsTheHMACKeyToCreativity'
U = string1 + t.y.to_bytes((t.y.bit_length()+7)//8, 'big') + t.x.to_bytes((t.x.bit_length()+7)//8, 'big')
Khmac = SHA3_256.new(U).digest()
print(Khmac)

#-----------------One-Time Pre-Key--------------
#create a nested array for getting the values of each OTK as an array inside of the main array
an_array = []

for i in range(0,10):
    to_del_array = [] #temporary array
    
    to_del_array.append(i) #inserting keyID to the array (0)
    OTK_priv = randint(1, n - 2) #private key generation
    OTK_pub = OTK_priv * P #public key generation
    to_del_array.append(OTK_priv) #inserting the private key to the array (1)
    to_del_array.append(OTK_pub) #inserting the public key to the  array (2)
    
    #defining the message to be signed
    m = OTK_pub.x.to_bytes((OTK_pub.x.bit_length()+7)//8, 'big') + OTK_pub.y.to_bytes((OTK_pub.y.bit_length()+7)//8, 'big')
    
    #creating an HMAC object and get its signature
    OTK_Kmac = hmac.HMAC(Khmac, digestmod=hashlib.sha256)
    OTK_Kmac.update(m)
    OTK_signature = OTK_Kmac.hexdigest()
    to_del_array.append(OTK_signature) #inserting the HMACI to the array (4)

    an_array.append(to_del_array) #inserting the array into the nested array

#Verifying 
for j in range(0, 10):
    OTKReg(an_array[j][0], an_array[j][2].x, an_array[j][2].y, an_array[j][3])
    print(an_array[j][1])
    
"""
"""
OTKs = [13184301596191533154574709226965699950542677362350456853961405151617853357744,114253597496309809724866931632449853012141887032707062604893974245979993800706,
        59034161473611544534434454886878083070817380672187640416096514359560621574004,29200056390088022644544715138068782512417246773305272664337232437294198431032,
        66525265432123638224092744254214040801530633499928504487557799082042551243508,67854266977448433471616112792875053738674123323604752505233168426386594326897,
        106240690876103138635898164237132553050803178058892182385543447552264377569254,57530441714188244087006505349496940827888779969308785073199415924286206096531,
        96860442342242929098279612503252666372061433234889026890386216875547963875794,104097561343177884814807911381751905033574065285934362017849868583503333250306]
h = 87641297249997788687989950206057398797033492263359553890287479745984043244527
s = 19977041033394878902609543645217874156114935795917822682947562560666751871036
IKpriv = 67662923314104435282664626284941289777438366070583458872054023206169890589609
KHMAC = b'\x1dmF]WZ\x93<~\xb9}I\xb2\x8e\xc2$\xc2l\xc5Pf\xb1\xfdTP\xc4\xe8w\xdbo\xe9z'
"""

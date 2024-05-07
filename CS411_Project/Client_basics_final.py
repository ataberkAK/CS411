#BATUHAN BOZTEPE-----28960-------ATABERK ASIL KARAMAN-----28945---------------#
import math
import time
import random
import sympy
import warnings
from random import randint, seed
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



def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def Setup():
    global E
    E = Curve.get_curve('secp256k1')
    return E

def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1,n-1)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(1, n-2)
    R = k*P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    s = (sA*h + k) % n
    return h, s

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P - h*QA
    v = V.x % n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False

stuID = 28960
stuIDB = 26045
curve = Setup()
#server's Identitiy public key
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)
print("In signature generation I fixed the random variable to 1748178 so that you can re-generate if you want")
def IKRegReq(h,s,x,y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(h,s,x,y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if(response.ok == False):
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID': stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    print(response.json())
#-----------------------------PHASE 3--------------------
def PseudoSendMsgPH3(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

def ReqMsg(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["MSGID"]

def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA': stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
    print(response.json())
    
#----------------------------NEW ONE----------------------------------    
def SendMsg(idA, idB, otkID, msgid, msg, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    
        
def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0

def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']
    
#--------------------------------PHASE 3--------------------------------------#
priv_k = 77130745935483247797972214598654445086751283460063310301073098601760064821023

"""
#We generated h,s for the id 26045
h = 76281157910321855811977508508442117044746011238571667900957143885831262916017
s = 52379608719676537921541011580859230864354046983260405949265127733165169990160
"""
h = 107113132909164862402153392981701239864481490775704809400284108024374036667855
s = 57139322410353434303360635805986030336717125563198459475397056574855802086106
#Then requested OTKs with the function reqOTKB
reqOTKB(28960, 26045, h, s)

"""
#KEYID, OTK came as these in the output

otk_k_ID = 951
otk_k_X = 85625339800165099654872474079453298270170692309503491053413876559057639351180
otk_k_Y = 103729283900995368530415858330222468146676897907079978971032739180430617847114
otk_pub = Point(otk_k_X, otk_k_Y, curve) #Point of OTK is generated with curve from Setup()

EKpriv, EKpub = KeyGen(curve) #Ephermal Key is generated with the KeyGen function
#print(EKpriv)
#print(EKpub)

#We put the messages that we decrypted in the Phase II in a list
messages = [b'https://www.youtube.com/watch?v=bc0KhhjJP98',b'INVALIDHMAC',b'https://www.youtube.com/watch?v=379oevm2fho',b'https://www.youtube.com/watch?v=ZZ05wrTJ_dI',b'https://www.youtube.com/watch?v=s3Nr-FoA9Ps']

#Key session is generated with the following process
T = otk_pub * EKpriv
U = (T.x.to_bytes((T.x.bit_length()+7)//8, 'big') + T.y.to_bytes((T.y.bit_length()+7)//8, 'big') + b'ToBeOrNotToBe')
K_session= SHA3_256.new(U).digest() 

#Key derivation funcction from Phase II
def KeyDer(Key):
    K_enc = SHA3_256.new(Key+ b'YouTalkingToMe').digest()
    K_hmac = SHA3_256.new(Key + K_enc + b'YouCannotHandleTheTruth').digest()
    K_kdf = SHA3_256.new(K_enc + K_hmac + b'MayTheForceBeWithYou').digest()
    return K_kdf, K_enc, K_hmac

#Lists to store KKDF, KEYENC, KHMAC
Kkdf_list = []
KeyEnc_list = []
Khmac_list = []
i = 0

#Iterating through our list of plaintexts
for msg in messages:
    
    #K_session will be used if we are starting the KDF chain
    if (len(Kkdf_list) == 0):
        K_kdf, K_enc, K_hmac = KeyDer(K_session)
    #Otherwise, KKDF from the previous iteration will be used
    else:
        K_kdf, K_enc, K_hmac = KeyDer(Kkdf_list[i - 1])
    i += 1
    
    #Encryption process
    cipher = AES.new(K_enc, AES.MODE_CTR)
    byte_nonce = cipher.nonce    
    plaintext_byte = msg
    ciphertext_b = cipher.encrypt(plaintext_byte)
    
    #HMAC generation
    hmac_hash = HMAC.new(msg = ciphertext_b, digestmod=SHA256, key=K_hmac)
    hmac_int = int.from_bytes(hmac_hash.digest(), byteorder='big') % curve.order
    hmac_b = hmac_int.to_bytes((hmac_int.bit_length() + 7) // 8, byteorder='big')
    
    block = byte_nonce + ciphertext_b + hmac_b
    MSG = int.from_bytes(block, byteorder='big')
    
    #Using the SendMsg function
    SendMsg(stuID, stuIDB, otk_k_ID, i, MSG, EKpub.x, EKpub.y)
    




#h,s of STUID = 28960
h1 = 68523139366795950486754622415195655430850812437249856069253018762611505420361
s1 = 9417609824715771387802774548980975212498193308584954190086907811282011135013

#We tried finish every OTK and check if restarts. 

PseudoSendMsgPH3(h1, s1)
ReqMsg(h1, s1)

#Checking the status of the inbox.
numMSG, numOTK, StatusMSG = Status(28960, h1, s1)

#Generating new OTKs if our OTKs extinct

KHMAC = b'\x1c\x99\xca\\6\x1fN\xd4\x8c\xf1n\x86\xe6\x88;\x0fg\xc3\xfamm\x03\xc3J\x99\xf1\xae#\x81\xa8z\x12'
#we keep the key of HMAC of to create new set of OTKs

if numOTK == 1:
    #You don't have any OTK left. Please register new OTKs.
    n = curve.order
    P = curve.generator
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
        OTK_Kmac = hmac.HMAC(KHMAC, digestmod=hashlib.sha256)
        OTK_Kmac.update(m)
        OTK_signature = OTK_Kmac.hexdigest()
        to_del_array.append(OTK_signature) #inserting the HMACI to the array (4)
    
        an_array.append(to_del_array) #inserting the array into the nested array
    
    #Verifying 
    for j in range(0, 10):
        OTKReg(an_array[j][0], an_array[j][2].x, an_array[j][2].y, an_array[j][3])
        print(an_array[j][1])
"""
        

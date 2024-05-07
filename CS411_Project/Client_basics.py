# Ataberk Asil Karaman 28945 // Batuhan Boztepe 28960
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
import base64
import hmac
import struct

API_URL = 'http://10.92.55.4:5000'

#In the first phase, we uploaded the code with Ataberk's stuID, but in this phase, we did it with Batuhan's stuID
stuID = 28960 #Batuhan Boztepe
#stuID = 28945 Ataberk Karaman
stuIDB = 18007

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

#server's Identitiy public key
#IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)

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
    print(response.json())

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
    print(response.json())

############## The new functions of phase 2 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

OTKs = [13184301596191533154574709226965699950542677362350456853961405151617853357744,114253597496309809724866931632449853012141887032707062604893974245979993800706,
        59034161473611544534434454886878083070817380672187640416096514359560621574004,29200056390088022644544715138068782512417246773305272664337232437294198431032,
        66525265432123638224092744254214040801530633499928504487557799082042551243508,67854266977448433471616112792875053738674123323604752505233168426386594326897,
        106240690876103138635898164237132553050803178058892182385543447552264377569254,57530441714188244087006505349496940827888779969308785073199415924286206096531,
        96860442342242929098279612503252666372061433234889026890386216875547963875794,104097561343177884814807911381751905033574065285934362017849868583503333250306]

h = 87641297249997788687989950206057398797033492263359553890287479745984043244527
s = 19977041033394878902609543645217874156114935795917822682947562560666751871036
IKpriv = 67662923314104435282664626284941289777438366070583458872054023206169890589609

E = Setup()
P = E.generator 
#PseudoSendMsg(h,s)

#OTK_priv from Phase I


"""
Sending message is:  {'ID': 28960, 'H': 87641297249997788687989950206057398797033492263359553890287479745984043244527, 'S': 19977041033394878902609543645217874156114935795917822682947562560666751871036}
{'IDB': 18007, 'OTKID': 2, 'MSGID': 1, 'MSG': 50114221755279042414102557066575733157734486643444536209092944516435033607158293220752280104072852652234395430240654087316589854791984817473302114109149641400518793829674157354526785741118336285277400, 'EK.X': 51335753283602528966020248898852093357756293702676131094568914776062795744871, 'EK.Y': 1302126871900205744495254686187513003323401177146198227887617308004677357217}
Sending message is:  {'ID': 28960, 'H': 87641297249997788687989950206057398797033492263359553890287479745984043244527, 'S': 19977041033394878902609543645217874156114935795917822682947562560666751871036}
{'IDB': 18007, 'OTKID': 2, 'MSGID': 2, 'MSG': 14907309755992920843080172791865420101842925408347414020685999360155932242648846723731389181848645783959231401305158440177253611288015486469756748057180273235204500490862190200330143486627237838498330, 'EK.X': 51335753283602528966020248898852093357756293702676131094568914776062795744871, 'EK.Y': 1302126871900205744495254686187513003323401177146198227887617308004677357217}
Sending message is:  {'ID': 28960, 'H': 87641297249997788687989950206057398797033492263359553890287479745984043244527, 'S': 19977041033394878902609543645217874156114935795917822682947562560666751871036}
{'IDB': 18007, 'OTKID': 2, 'MSGID': 3, 'MSG': 56947226439051463541740986731369433724040860933784041369712173820113640460069455953875351060033339323329716002451439958451960750993694879980641599256057127094897358794099491379345143206135305818035799, 'EK.X': 51335753283602528966020248898852093357756293702676131094568914776062795744871, 'EK.Y': 1302126871900205744495254686187513003323401177146198227887617308004677357217}
Sending message is:  {'ID': 28960, 'H': 87641297249997788687989950206057398797033492263359553890287479745984043244527, 'S': 19977041033394878902609543645217874156114935795917822682947562560666751871036}
{'IDB': 18007, 'OTKID': 2, 'MSGID': 4, 'MSG': 45618257047561634981643765529373317006702673165349762014278187961193468381635048289054239758231730000487758513548727885229611291512319461775435117484656979840186546883726539419063688819486531598716176, 'EK.X': 51335753283602528966020248898852093357756293702676131094568914776062795744871, 'EK.Y': 1302126871900205744495254686187513003323401177146198227887617308004677357217}
Sending message is:  {'ID': 28960, 'H': 87641297249997788687989950206057398797033492263359553890287479745984043244527, 'S': 19977041033394878902609543645217874156114935795917822682947562560666751871036}
{'IDB': 18007, 'OTKID': 2, 'MSGID': 5, 'MSG': 32334317087164039832603145335169597261126862619358497467137656706770032943919290331199880941949006749084113153047813134752098325486667874630675535140961119566735383394071065232642368424547691544251171, 'EK.X': 51335753283602528966020248898852093357756293702676131094568914776062795744871, 'EK.Y': 1302126871900205744495254686187513003323401177146198227887617308004677357217}
"""

#Generating the Ephermal Key Point with the information from the messages that we received
ek_m = Point(51335753283602528966020248898852093357756293702676131094568914776062795744871,1302126871900205744495254686187513003323401177146198227887617308004677357217, E)
msg1 = 50114221755279042414102557066575733157734486643444536209092944516435033607158293220752280104072852652234395430240654087316589854791984817473302114109149641400518793829674157354526785741118336285277400
msg2 = 14907309755992920843080172791865420101842925408347414020685999360155932242648846723731389181848645783959231401305158440177253611288015486469756748057180273235204500490862190200330143486627237838498330
msg3 = 56947226439051463541740986731369433724040860933784041369712173820113640460069455953875351060033339323329716002451439958451960750993694879980641599256057127094897358794099491379345143206135305818035799
msg4 = 45618257047561634981643765529373317006702673165349762014278187961193468381635048289054239758231730000487758513548727885229611291512319461775435117484656979840186546883726539419063688819486531598716176
msg5 = 32334317087164039832603145335169597261126862619358497467137656706770032943919290331199880941949006749084113153047813134752098325486667874630675535140961119566735383394071065232642368424547691544251171
#A list for all the received messages
messages = [msg1,msg2,msg3,msg4,msg5]
OTK_A_priv = 59034161473611544534434454886878083070817380672187640416096514359560621574004
#------------- 3.1.1 // Generating The Session Key ---------------------------
T = OTK_A_priv * ek_m
U = (T.x.to_bytes((T.x.bit_length()+7)//8, 'big') + T.y.to_bytes((T.y.bit_length()+7)//8, 'big') + b'ToBeOrNotToBe')
K_session= SHA3_256.new(U).digest() 

#-------------3.1.2 // Key Derivation Funciton Chain---------------------------

def KeyDer(Key):
    K_enc = SHA3_256.new(Key+ b'YouTalkingToMe').digest()
    K_hmac = SHA3_256.new(Key + K_enc + b'YouCannotHandleTheTruth').digest()
    K_kdf = SHA3_256.new(K_enc + K_hmac + b'MayTheForceBeWithYou').digest()
    return K_kdf, K_enc, K_hmac

#Different variables for the keys that are generated from the KDF chain
K_kdf, K_enc, K_hmac = KeyDer(K_session)
#print(K_kdf,"=========", K_enc,"=========", K_hmac, "\n")
K_kdf1, K_enc1, K_hmac1 = KeyDer(K_kdf)
#print(K_kdf1,"=========", K_enc1,"=========", K_hmac, "\n")
K_kdf2, K_enc2, K_hmac2 = KeyDer(K_kdf1)
#print(K_kdf2,"=========", K_enc2,"=========", K_hmac, "\n")
K_kdf3, K_enc3, K_hmac3 = KeyDer(K_kdf2)
#print(K_kdf3,"=========", K_enc3,"=========", K_hmac, "\n")
K_kdf4, K_enc4, K_hmac4 = KeyDer(K_kdf3)
#print(K_kdf4,"=========", K_enc4,"=========", K_hmac, "\n")

#------------3.3 // Decyrpting the messages-----------------------------------
def decMsg(cText, K_enc, K_hmac):

    MSG_bytes = cText.to_bytes((cText.bit_length() + 7) // 8, byteorder="big") 
    #msg = nonce || ciphertext || MAC is the message format
    nonce = MSG_bytes[:8] #Slicing for the nonce
    ciphertext = MSG_bytes[8 :-32] #Slicing for the ciphertext
    mac = MSG_bytes[-32:] #Size of the MAC is 256 bits (32 bytes)

    #Creating the K_hmac_new to compare it with the mac
    Hmac = HMAC.new(K_hmac, digestmod=SHA256)
    K_hmac_new = Hmac.update(ciphertext).digest()

    #Checking HMAC
    if K_hmac_new == mac:
        print("HMAC is correct!")
    else:  
        print("HMAC is not correct!")
        return "INVALIDHMAC"
    
    #Finding the decmsg by decrypting the cipher
    cipher = AES.new(K_enc, AES.MODE_CTR, nonce = nonce)
    try:
        decmsg = cipher.decrypt(ciphertext).decode('utf-8')
        return decmsg
    except:
        if K_hmac_new == mac:
            cipher = AES.new(K_enc, AES.MODE_CTR, nonce = nonce)
            decmsg = cipher.decrypt(ciphertext).decode("utf-8")
            return decmsg
    else:
        return "INVALIDHMAC"

Checker(stuID, stuIDB, 1, decMsg(messages[0], K_enc, K_hmac))
Checker(stuID, stuIDB, 2, decMsg(messages[1], K_enc1, K_hmac1))
Checker(stuID, stuIDB, 3, decMsg(messages[2], K_enc2, K_hmac2))
Checker(stuID, stuIDB, 4, decMsg(messages[3], K_enc3, K_hmac3))
Checker(stuID, stuIDB, 5, decMsg(messages[4], K_enc4, K_hmac4))

"""
HMAC is correct!
Sending message is:  {'IDA': 28960, 'IDB': 18007, 'MSGID': 1, 'DECMSG': 'https://www.youtube.com/watch?v=379oevm2fho'}
You decrypted it correctly, wow!
HMAC is correct!
Sending message is:  {'IDA': 28960, 'IDB': 18007, 'MSGID': 2, 'DECMSG': 'https://www.youtube.com/watch?v=CvjoXdC-WkM'}
You decrypted it correctly, wow!
HMAC is correct!
Sending message is:  {'IDA': 28960, 'IDB': 18007, 'MSGID': 3, 'DECMSG': 'https://www.youtube.com/watch?v=CvjoXdC-WkM'}
You decrypted it correctly, wow!
HMAC is correct!
Sending message is:  {'IDA': 28960, 'IDB': 18007, 'MSGID': 4, 'DECMSG': 'https://www.youtube.com/watch?v=CvjoXdC-WkM'}
You decrypted it correctly, wow!
HMAC is not correct!
Sending message is:  {'IDA': 28960, 'IDB': 18007, 'MSGID': 5, 'DECMSG': 'INVALIDHMAC'}
You've found the faulty message. Good job!
"""    


#-------------------3.4 Displaying the Final Message---------------------------

decMessages = ['https://www.youtube.com/watch?v=379oevm2fho','https://www.youtube.com/watch?v=CvjoXdC-WkM','https://www.youtube.com/watch?v=CvjoXdC-WkM','https://www.youtube.com/watch?v=CvjoXdC-WkM','INVALIDHMAC']

deleted = ReqDelMsg(h, s)
if deleted == None:
    for i in range(0,5):
        if(decMessages[i] == "INVALIDHMAC"):
            continue
        else:
            print("Message ",i+1,"- ", decMessages[i], "- Read")
else:
    for i in range (0,5):
        if (i+1 in deleted and decMessages[i] != "INVALIDHMAC"):        
            print("Message ", i+1, "- was deleted by the Sender - 18007")
            continue
        elif (decMessages[i] == "INVALIDHMAC"):
            continue
        else:
            print("Message ",i+1,"- ", decMessages[i], "- Read")


    
  
    
    
    
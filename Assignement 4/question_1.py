import random
import requests
from random import randint

API_URL = 'http://10.92.55.4:6000'
my_id = 28945

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
def RSA_Oracle_Get():
  response = requests.get('{}/{}/{}'.format(API_URL, "RSA_Oracle", my_id)) 	
  c, N, e = 0,0,0 
  if response.ok:	
    res = response.json()
    print(res)
    return res['c'], res['N'], res['e']
  else:
    print(response.json())

def RSA_Oracle_Query(c_):
  response = requests.get('{}/{}/{}/{}'.format(API_URL, "RSA_Oracle_Query", my_id, c_)) 
  print(response.json())
  m_= ""
  if response.ok:	m_ = (response.json()['m_'])
  else: print(response)
  return m_

def RSA_Oracle_Checker(m):
  response = requests.put('{}/{}/{}/{}'.format(API_URL, "RSA_Oracle_Checker", my_id, m))
  print(response.json())

## THIS IS ONLY AN EMPTY CLIENT CODE, YOU HAVE TO EXTRACT M
## THEN CHECK IT USING THE CHECKING ORACLE.

c, N, e = RSA_Oracle_Get()

c = 10248283460753635060162885273648916119754528267805869201239550599075586265934468933915730964660271814163045535270773579132952818649531272483109849392060794789756099413763148203313181575496201055713483718506706465287950083406645616576926463912384490482308131852380612421733301005295533811033482847834868661936347751670890641446567539005022238721907386578371603814868132351643320473024843430637595823397182091815323961706792654219842004118038791300764106672656202722761054819806171211277684671224900156989982947676893018353856573831500575697940810352024369989228776978685349297233008310479100939562503042099947395689208
N = 16939269462313198277725089002524968140769895904731797247921693446825361577176513265093962001473249149493514478809355121972226854971742591412020947781343582572258409348854687792672350790838706795045105779549770778632847428289027972956461589642862664604406205649788062899700494060455208957227204718515101331592572887762868780071870612248382350488623041960895952847347193036811161635348404536654480418700288618890111185617389009319953809419282210422869145631879305871459779170673590029863798266603861263916454445940018625253525716638055179599474296505004768081393212277916373461197482274715508530005125354616487101316387
e = 65537
# know that this is a choosen cipertext attack, which means that main crypting formula is; c = m^e mod N
# and we need the key k extracted from formula; m = c^k mod N

gcd, x, y = egcd(c,3)
print(gcd)
r = 3
# we found a random number r = 3 which has no common divisor with c, we will use it as a fake decyper key

c_ = (c * (r**e)) % N
# now with c_ we get we can get the key value with sending c_ 
m_ = RSA_Oracle_Query(c_)
m = (m_ * modinv(r, N)) % N

mText = m.to_bytes((m.bit_length() // 8 + 1), byteorder="big").decode()

print(mText)

RSA_Oracle_Checker(mText) ## m should be a string

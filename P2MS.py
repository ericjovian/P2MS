import os, sys, random
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import binascii

pub = []
priv = []

key_pem = "-----BEGIN PUBLIC KEY-----\n\
MIIBtjCCASsGByqGSM44BAEwggEeAoGBAMru3+fqTHjUXRjgmXBzxtEMXceRdXVK\n\
SxQYWEb2zHFkc8MVBxE41Cgv9sVsNTFI9VsIlVrSyXHeUJ6LKznZOjC5qWEawR9E\n\
bBpCZlc0uDjc8NbQ9MFQkgw0TmERn/Xg1SjY8z6aaVR8BwT6/Bt/63AxdOmH9UPK\n\
ullMaqDruzplAhUAmzGsd2tN44X8WEdvdK+RKIj/SasCgYAmyasijKGmEDEJZrR0\n\
TPDxPFas8MlyPNSYj4zokNm5JG/2DsDoAyVlGQkRgEjET3a15OQazLRX2FC9hRZI\n\
XH87TLH2XyTzm9SzBBmKcfF8r/kyoWfNkDq6kU27RWZO6oVPZqrNi5T+ncS5amnM\n\
AUiij85K0LaIYPxczZL1s2qGhAOBhAACgYAlD9gc7GKnLQ4N4yfZrAdoAxkXpNSC\n\
xN9d8FUsuADHjgMMybDKOGyELdLn5dDOFRZd4qnykEndEuM5hZqBZPWHBj3AJ5Xd\n\
XXnWzMay1oatMHKPs1mi1wVKgtsk2GZu/OEJm2y/lEZfNUTA6jc/Q9Jqiemh2dOm\n\
AOf/PuTH08Td3Q==\n\
-----END PUBLIC KEY-----\n\
"

param_key = DSA.import_key(key_pem)
param = [param_key.p, param_key.q,param_key.g] 

def generate_key():
    key = DSA.generate(1024,domain= param)
    #public and private key generated in variable
    pub_key = key.publickey().exportKey()
    priv_key = key.exportKey()

    return(pub_key, priv_key)

#signature
def signature(privatefile):
    message = b'CSCI301 Contemporary topic in security'
    key = DSA.import_key(open(privatefile).read())
    os.remove(privatefile)
    h = SHA256.new(message)
    signer = DSS.new(key, 'fips-186-3')
    signatu = signer.sign(h)
    signature_hex = binascii.hexlify(signatu)
    return signature_hex

#pubkey
def pubkey(pub_key):
    key = DSA.importKey(pub_key)
    tup = [key.y, key.g, key.p, key.q]
    return hex(tup[0])

def privkey(priv_key):
    with open('privatekey.txt','wb') as f:
        f.write(priv_key)
    sig = signature('privatekey.txt')
    sig = sig.decode("utf-8")
    return sig

def main():
    pub_key, priv_key = generate_key()
    pub.append(pubkey(pub_key))
    priv.append(privkey(priv_key))


def shellarg():
    M = int(sys.argv[1])
    N = int(sys.argv[2])
    if M > N:
        print("N have to be equal to or greater than M")
    elif 1 <= M <= 10 and 1 <= N <= 10:
        count = 0
        while count < N:
            main()
            count += 1
        with open('scriptPubKey.txt','w') as f:
            f.write("OP_"+str(M)+"\n")
            for x in pub:
                f.write(str(x)+"\n")
            f.write("OP_"+str(N)+" OP_CHECKMULTISIG")
        with open('scriptSig.txt','w') as f:
            f.write("OP_1\n")
            rando = random.sample(range(N), M)
            for i in rando:
                f.write(str(priv[i])+"\n")
    else:
        print("please use a number from 1 to 10")

shellarg()
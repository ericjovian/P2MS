from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import binascii, sys

def stack(a,b):
    with open(a,'r') as f:
        sig = f.read().split('\n')

    sig.pop()
    sigshow = []
    for i in sig:
        sigshow.append(i)
    sig.pop(0)

    with open(b,'r') as f:
        pub = f.read().split('\n')

    pubshow = pub
    print('\n')
    print("scriptSig and scriptPubKey are combined.")
    c = sigshow + pub
    for item in c:
        print(item, end=" ")

    print('\n')
    print("Constants from scriptSig are added to the stack.")
    print("1")
    for item in sig:
        print(item, end="\n")

    print('\n')
    print("Constants from scriptPubKey are added to the stack.")
    print("1")
    for item in sig:
        print(item, end="\n")
    pub = [i.strip('OP_') for i in pub]
    pub = [i.strip(' OP_CHECKMULTISIG') for i in pub]
    for item in pub:
        print(item, end="\n")
    print('\n')
    pub.pop()
    pub.pop(0)

    return(pub, sig)


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
param = [param_key.g,param_key.p, param_key.q] 
def verify(a,b):
    y = int(a,16)
    tup = [y, param[0], param[1], param[2]]
    key = DSA.construct(tup)

    message = b'CSCI301 Contemporary topic in security'
    hash_obj = SHA256.new(message)
    verifier = DSS.new(key, 'fips-186-3')
    signature = binascii.unhexlify(b)
    try:
        verifier.verify(hash_obj, signature)
        return True 
    except ValueError:
        return False

def shellarg():
    a = sys.argv[1]
    b = sys.argv[2]
    counter = []
    pub, sig = stack(a, b)
    for i in range(len(pub)):
        for j in range(len(sig)):
            counter.append(verify(pub[i], sig[j]))

    get_indexes = lambda x, xs: [i for (y, i) in zip(xs, range(len(xs))) if x == y]
    if len(get_indexes(True,counter)) == len(sig):
        print("All Signature are authenthic and verified")
    else:
        print("Not Authenthic")

shellarg()


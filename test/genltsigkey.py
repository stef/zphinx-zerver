import pysodium

pk, sk = pysodium.crypto_sign_keypair()
with open(f"ltsig.key", 'wb') as fd:
   fd.write(sk)

with open(f"ltsig.pub", 'wb') as fd:
   fd.write(pk)

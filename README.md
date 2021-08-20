# Overview

Israel Ministry of Health Green Pass is signed using a private key, and can
be verified by checking its signature using the corresponding public key.

Ministry of Health published two such public keys 
([RSA](https://github.com/MohGovIL/Ramzor/blob/main/Verification/RSA/RamzorQRPubKey.der) 
and [ECDSA](https://github.com/MohGovIL/Ramzor/blob/main/Verification/ECDSA/RamzorQRPubKeyEC.der)) 
for some types of green passes, but other types of green passes are signed using
a different private key (and hence, public key).

This script can derive such unpublished ECDSA public keys from at least two valid Green 
Pass signatures, produced using the corresponding private key.

# Usage

Edit the variables `GREEN_PASS_QR_VALUES` and replace the reference QR codes values
with at least two valid QR code values that are using the public key you wish to
obtain (for example, QR codes of "fast tests").

Run the script to obtain the public key in PEM format.

# Referene QR Code Values

The reference QR code values are from
https://github.com/MohGovIL/Ramzor/tree/main/Verification/ECDSA/Sample%20data.

To observe that the public key produced by the reference values is correct,
compare it to the reference key in 
https://github.com/MohGovIL/Ramzor/blob/main/Verification/ECDSA/RamzorQRPubKeyEC.der -

```
openssl x509 -in RamzorQRPubKeyEC.der -inform der -noout -pubkey
```

The reference public key (from RamzorQRPubKeyEC.der), and the key produced by
the script are -

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVD+aucpFLPK3HNnaZ/T/HeFGW84a
gCBnW0Je0CzzDjhWNdNgI0R74uMhqVAiAFOH2NPjPXgQmaNSpdwRhlGXTw==
-----END PUBLIC KEY-----
```

## License

[Apache License 2.0](LICENSE).

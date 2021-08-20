import ecc_calculations

import asn1
import base64


#
# Reference green pass QR codes taken from
# https://github.com/MohGovIL/Ramzor/tree/main/Verification/ECDSA/Sample%20data.
#
# REMOVE THESE QR CODE VALUES AND REPLACE WITH YOUR OWN!
# (two are sufficient to derive the correct public key)
#
GREEN_PASS_QR_VALUES = [
    # Sample-VacCertificate1.pdf -
    'MEUCIDa4q2Z9OeZ8cY6dDO5FvJrRcUmpwwLY3cASgGAA7B73AiEAjA0FXq42rp1vh314h8QnSGvWRFTNhIHVflFO0zdSW14=#{"id":"01/IL/FF22E568F0064351A489482A1937CA36#670355A2","et":3,"c":"IL MOHEC","ct":6,"g":"Moshe","f":"Cohen","gl":"משה","fl":"כהן","idl":"120456739","idp":"00981065432","b":"1990-02-07","e":"2021-08-14 00:00:00","a":"2021-02-15","ps":"Vaccinated","d1":{"d":"2021-02-08","vv":"Pfizer","vt":"covid19","vb":"BNT162b2","vc":"208","o":"clalit","ol":"כללית","oc":"1","c":"ISR"},"d2":{"d":"2021-01-17","vv":"Pfizer","vt":"covid19","vb":"BNT162b2","vc":"208","o":"clalit","ol":"כללית","oc":"1","c":"ISR"},"rd":"2021-05-23"}',
    # Sample-VacCertificate2.pdf -
    'MEQCIGGkU6uH8NejSSX20hkp3SgB/wT2LtCXAfBKKVFivXW1AiAaXJQA2uKpz7VR8uMZs9EW6E3aT9kw5zqgislcVmxDTQ==#{"id":"01/IL/40F0B29B2AA4610B9476C04147B52B32#5F1D1701","et":3,"c":"IL MOHEC","ct":6,"g":"David","f":"Badlin","gl":"דוד","fl":"בדלין","idl":"212109876","idp":"0012345678","b":"1991-10-12","e":"2021-08-23 00:00:00","a":"2021-02-24","ps":"Vaccinated","d1":{"d":"2021-02-17","vv":"Pfizer","vt":"covid19","vb":"BNT162b2","vc":"208","o":"clalit","ol":"כללית","oc":"1","c":"ISR"},"d2":{"d":"2021-01-27","vv":"Pfizer","vt":"covid19","vb":"BNT162b2","vc":"208","o":"clalit","ol":"כללית","oc":"1","c":"ISR"},"rd":"2021-05-20"}',
    # Sample-VacCertificate3.pdf -
    'MEUCIQD/8bdhDLmX+xRaUC+kzx+7Ks9Q0HhxDhmCkbzdQEVP2QIgJSquKMehylOTtK2wJsE/pFEvQfqv4IO9DvhpEiY2muw=#{"id":"01/IL/DBC1EB6016F9BF506DA63FA9536AC683#E3503210","et":3,"c":"IL MOHEC","ct":6,"g":"David","f":"Badlin","gl":"דוד","fl":"בדלין","idl":"212109876","idp":"0012345678","b":"1991-10-12","e":"2021-11-28 00:00:00","a":"2021-05-28","ps":"Vaccinated","d1":{"d":"2021-05-21","vv":"Pfizer","vt":"covid19","vb":"BNT162b2","vc":"208","o":"clalit","ol":"כללית","oc":"1","c":"ISR"},"d2":{"d":"2021-05-01","vv":"Pfizer","vt":"covid19","vb":"BNT162b2","vc":"208","o":"clalit","ol":"כללית","oc":"1","c":"ISR"},"rd":"2021-05-20"}',
]


# Convert an ASN.1 DER signature to IEEE P1363 binary signature.
# ASN.1 DER signature is defined in https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3 -
#   Ecdsa-Sig-Value  ::=  SEQUENCE  {
#     r     INTEGER,
#     s     INTEGER  }
# Binary signature is simply r and s in big-endian padded to 32 bytes, concatenated.
def asn1_to_binary_signature(signature_asn1):
    decoder = asn1.Decoder()
    decoder.start(signature_asn1)

    tag = decoder.peek()
    assert (tag.typ == asn1.Types.Constructed)
    decoder.enter()

    tag = decoder.read()
    assert (tag[0].nr == asn1.Numbers.Integer)
    assert (tag[0].typ == asn1.Types.Primitive)
    r = tag[1]

    tag = decoder.read()
    assert (tag[0].nr == asn1.Numbers.Integer)
    assert (tag[0].typ == asn1.Types.Primitive)
    s = tag[1]

    tag = decoder.read()
    assert (tag is None)

    signature = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

    return signature


def main():

    messages_and_signatures = []
    for green_pass_qr_value in GREEN_PASS_QR_VALUES:
        (signature_der_base64, message_str) = green_pass_qr_value.split("#", 1)

        signature_der = base64.b64decode(signature_der_base64)
        signature = asn1_to_binary_signature(signature_der)

        message = message_str.encode("utf-8")

        messages_and_signatures.append([message, signature])

    # Derive public key that matches all signatures.
    public_keys = ecc_calculations.public_keys_from_multiple_signatures(messages_and_signatures)

    if len(public_keys) == 0:
        print("No public keys identified matching all signatures.")
    else:
        print("Public keys identified matching all signatures -")
        for public_key in public_keys:
            print(public_key)
            print(public_key.export_key(format="PEM"))


main()

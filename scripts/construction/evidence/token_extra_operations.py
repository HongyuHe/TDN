#!/usr/bin/env python3
"""Observe additional PKCS11 operations without exporting secret values."""

import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path

import PyKCS11 as p
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


FUNCTIONS = """Initialize Finalize GetInfo GetFunctionList GetSlotList GetSlotInfo GetTokenInfo
GetMechanismList GetMechanismInfo InitToken InitPIN SetPIN OpenSession CloseSession CloseAllSessions
GetSessionInfo GetOperationState SetOperationState Login Logout CreateObject CopyObject DestroyObject
GetObjectSize GetAttributeValue SetAttributeValue FindObjectsInit FindObjects FindObjectsFinal
EncryptInit Encrypt EncryptUpdate EncryptFinal DecryptInit Decrypt DecryptUpdate DecryptFinal
DigestInit Digest DigestUpdate DigestKey DigestFinal SignInit Sign SignUpdate SignFinal SignRecoverInit
SignRecover VerifyInit Verify VerifyUpdate VerifyFinal VerifyRecoverInit VerifyRecover DigestEncryptUpdate
DecryptDigestUpdate SignEncryptUpdate DecryptVerifyUpdate GenerateKey GenerateKeyPair WrapKey UnwrapKey
DeriveKey SeedRandom GenerateRandom GetFunctionStatus CancelFunction WaitForSlotEvent""".split()
FUNCTIONS_3 = """GetInterfaceList GetInterface LoginUser SessionCancel MessageEncryptInit EncryptMessage
EncryptMessageBegin EncryptMessageNext MessageEncryptFinal MessageDecryptInit DecryptMessage
DecryptMessageBegin DecryptMessageNext MessageDecryptFinal MessageSignInit SignMessage SignMessageBegin
SignMessageNext MessageSignFinal MessageVerifyInit VerifyMessage VerifyMessageBegin VerifyMessageNext
MessageVerifyFinal""".split()
U = c.c_ulong
P = c.c_void_p


class Functions(c.Structure):
    _fields_ = [("version", c.c_ubyte * 2)] + [("C_" + name, P) for name in FUNCTIONS]


class Functions3(c.Structure):
    _fields_ = [("version", c.c_ubyte * 2)] + [("C_" + name, P) for name in FUNCTIONS + FUNCTIONS_3]


class Interface(c.Structure):
    _fields_ = [("name", c.c_char_p), ("functions", P), ("flags", U)]


class Attribute(c.Structure):
    _fields_ = [("kind", U), ("value", P), ("length", U)]


class Mechanism(c.Structure):
    _fields_ = [("kind", U), ("parameter", P), ("length", U)]


class ECDH(c.Structure):
    _fields_ = [("kdf", U), ("sharedLength", U), ("shared", P), ("publicLength", U), ("public", P)]


class Version(c.Structure):
    _fields_ = [("major", c.c_ubyte), ("minor", c.c_ubyte)]


class Information(c.Structure):
    _fields_ = [("cryptokiVersion", Version), ("manufacturer", c.c_char * 32), ("flags", U),
                ("description", c.c_char * 32), ("libraryVersion", Version)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    args = parser.parse_args()
    credentials = json.loads(args.credentials.read_text())
    certificate_bytes = Path("/etc/swanctl/x509/cert.pem").read_bytes()
    certificate = x509.load_pem_x509_certificate(certificate_bytes)
    public = certificate.public_key()
    module = c.CDLL(args.module)
    table = c.POINTER(Functions)()
    module.C_GetFunctionList.argtypes = [c.POINTER(c.POINTER(Functions))]
    module.C_GetFunctionList.restype = U
    assert module.C_GetFunctionList(c.byref(table)) == 0
    operations = []

    def call(name, types, arguments, required=False):
        code = c.CFUNCTYPE(U, *types)(getattr(table.contents, "C_" + name))(*arguments)
        operations.append({"operation": "C_" + name, "returnCode": code})
        if required:
            assert code == 0, "Required API setup failed: " + name + ": " + str(code)
        return code

    call("Initialize", [P], [None], True)
    information = Information()
    call("GetInfo", [c.POINTER(Information)], [c.byref(information)], True)
    api = {"functionListVersion": list(table.contents.version),
           "cryptokiVersion": [information.cryptokiVersion.major, information.cryptokiVersion.minor],
           "libraryVersion": [information.libraryVersion.major, information.libraryVersion.minor],
           "manufacturer": bytes(information.manufacturer).decode().strip(),
           "description": bytes(information.description).decode().strip(),
           "callableFunctions": ["C_" + name for name in FUNCTIONS if getattr(table.contents, "C_" + name)],
           "directSymbols": {name: getattr(module, name, None) is not None
                             for name in ["C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList"]}}
    module.C_GetInterfaceList.argtypes = [c.POINTER(Interface), c.POINTER(U)]
    module.C_GetInterfaceList.restype = U
    interface_count = U()
    assert module.C_GetInterfaceList(None, c.byref(interface_count)) == 0
    interfaces = (Interface * interface_count.value)()
    assert module.C_GetInterfaceList(interfaces, c.byref(interface_count)) == 0
    api["interfaces"] = []
    for interface in interfaces:
        version = list(c.cast(interface.functions, c.POINTER(Functions)).contents.version)
        known = version in [[2, 40], [3, 0]]
        layout = Functions3 if version == [3, 0] else Functions
        view = c.cast(interface.functions, c.POINTER(layout)).contents
        names = FUNCTIONS + FUNCTIONS_3 if version == [3, 0] else FUNCTIONS
        api["interfaces"].append({"name": interface.name.decode(), "version": version, "flags": interface.flags,
                                  "knownLayout": known,
                                  "callableFunctions": ["C_" + name for name in names if getattr(view, "C_" + name)]
                                  if known else []})
    count = U()
    call("GetSlotList", [c.c_ubyte, c.POINTER(U), c.POINTER(U)], [1, None, c.byref(count)], True)
    slots = (U * count.value)()
    call("GetSlotList", [c.c_ubyte, c.POINTER(U), c.POINTER(U)], [1, slots, c.byref(count)], True)
    assert count.value == 1
    session = U()
    call("OpenSession", [U, U, P, P, c.POINTER(U)],
         [slots[0], p.CKF_SERIAL_SESSION | p.CKF_RW_SESSION, None, None, c.byref(session)], True)
    pin = credentials["pin"].encode()
    call("Login", [U, U, c.c_char_p, U], [session, p.CKU_USER, pin, len(pin)], True)
    key_class, key_id = U(p.CKO_PRIVATE_KEY), c.c_ubyte(1)
    template = (Attribute * 2)(Attribute(p.CKA_CLASS, c.cast(c.byref(key_class), P), c.sizeof(key_class)),
                               Attribute(p.CKA_ID, c.cast(c.byref(key_id), P), 1))
    call("FindObjectsInit", [U, c.POINTER(Attribute), U], [session, template, 2], True)
    handles = (U * 2)()
    count = U()
    call("FindObjects", [U, c.POINTER(U), U, c.POINTER(U)], [session, handles, 2, c.byref(count)], True)
    call("FindObjectsFinal", [U], [session], True)
    assert count.value == 1
    key = handles[0]
    mechanism = Mechanism(p.CKM_ECDSA, None, 0)
    call("SignInit", [U, c.POINTER(Mechanism), U], [session, c.byref(mechanism), key], True)
    challenge = hashlib.sha384(b"TDN v3.1 extra API key binding").digest()
    signature = (c.c_ubyte * 128)()
    length = U(128)
    call("Sign", [U, c.c_char_p, U, P, c.POINTER(U)],
         [session, challenge, len(challenge), signature, c.byref(length)], True)
    signed = bytes(signature[:length.value])
    assert len(signed) == 96
    der_signature = utils.encode_dss_signature(int.from_bytes(signed[:48], "big"), int.from_bytes(signed[48:], "big"))
    public.verify(der_signature, challenge, ec.ECDSA(utils.Prehashed(hashes.SHA384())))
    mechanism = Mechanism(p.CKM_SHA384, None, 0)
    call("DigestInit", [U, c.POINTER(Mechanism)], [session, c.byref(mechanism)], True)
    digest_key_code = call("DigestKey", [U, U], [session, key])
    state_length = U()
    state_code = call("GetOperationState", [U, P, c.POINTER(U)], [session, None, c.byref(state_length)])
    digest = (c.c_ubyte * 64)()
    digest_length = U(64)
    digest_final_code = call("DigestFinal", [U, P, c.POINTER(U)], [session, digest, c.byref(digest_length)])
    digest_reference = hashlib.sha256(bytes(digest[:digest_length.value])).hexdigest() if digest_final_code == 0 else None
    iv = (c.c_ubyte * 16)()
    mechanism = Mechanism(p.CKM_AES_CBC, c.cast(iv, P), 16)
    decrypt_code = call("DecryptInit", [U, c.POINTER(Mechanism), U], [session, c.byref(mechanism), key])
    point_bytes = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    point = c.create_string_buffer(point_bytes)
    parameters = ECDH(p.CKD_NULL, 0, None, len(point_bytes), c.cast(point, P))
    mechanism = Mechanism(p.CKM_ECDH1_DERIVE, c.cast(c.byref(parameters), P), c.sizeof(parameters))
    derived_class, derived_type, derived_length = U(p.CKO_SECRET_KEY), U(p.CKK_GENERIC_SECRET), U(48)
    derived_template = (Attribute * 3)(
        Attribute(p.CKA_CLASS, c.cast(c.byref(derived_class), P), c.sizeof(U)),
        Attribute(p.CKA_KEY_TYPE, c.cast(c.byref(derived_type), P), c.sizeof(U)),
        Attribute(p.CKA_VALUE_LEN, c.cast(c.byref(derived_length), P), c.sizeof(U)))
    derived_handle = U()
    derive_code = call("DeriveKey", [U, c.POINTER(Mechanism), U, c.POINTER(Attribute), U, c.POINTER(U)],
                       [session, c.byref(mechanism), key, derived_template, 3, c.byref(derived_handle)])
    call("Logout", [U], [session], True)
    call("CloseSession", [U], [session], True)
    call("Finalize", [P], [None], True)
    spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    print(json.dumps({"label": credentials["label"], "keyIdHex": "01", "operations": operations, "api": api,
                      "digestKeyCode": digest_key_code, "digestFinalCode": digest_final_code,
                      "digestBytes": digest_length.value if digest_final_code == 0 else 0,
                      "digestReferenceSha256": digest_reference, "digestBytesExported": False,
                      "operationStateCode": state_code, "operationStateBytesExported": False,
                      "deriveCode": derive_code, "decryptInitCode": decrypt_code,
                      "publicSPKISha256": hashlib.sha256(spki).hexdigest(),
                      "certificateSha256": hashlib.sha256(certificate_bytes).hexdigest(),
                      "signatureVerified": True, "challengeDigestHex": challenge.hex(), "signatureHex": signed.hex()},
                     sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Operate a laboratory token and export only public attributes and outcomes."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path

import PyKCS11 as p
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def public_key(session, handle):
    raw = bytes(session.getAttributeValue(handle, [p.CKA_EC_POINT])[0])
    length = raw[1]
    start = 2
    if length & 128:
        count = length & 127
        length = int.from_bytes(raw[2:2 + count], "big")
        start += count
    assert raw[0] == 4 and len(raw) == start + length
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), raw[start:])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["initialize", "generate", "exercise"])
    parser.add_argument("--module", required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--public-output", type=Path)
    args = parser.parse_args()
    credentials = json.loads(args.credentials.read_text())
    library = p.PyKCS11Lib()
    library.load(args.module)
    if args.action == "initialize":
        slot = library.getSlotList(tokenPresent=False)[0]
        library.initToken(slot, credentials["soPin"], credentials["label"].ljust(32))
        slot = library.getSlotList(tokenPresent=True)[0]
        session = library.openSession(slot, p.CKF_SERIAL_SESSION | p.CKF_RW_SESSION)
        session.login(credentials["soPin"], p.CKU_SO)
        session.initPin(credentials["pin"])
        session.logout()
        session.closeSession()
        print(json.dumps({"initialized": True, "label": credentials["label"], "slot": slot}))
        return
    slots = [slot for slot in library.getSlotList(tokenPresent=True)
             if library.getTokenInfo(slot).label.strip() == credentials["label"]]
    assert len(slots) == 1, "Expected one selected remote token"
    slot = slots[0]
    session = library.openSession(slot, p.CKF_SERIAL_SESSION | p.CKF_RW_SESSION)
    session.login(credentials["pin"])
    identity = (1,)
    if args.action == "generate":
        public_template = [(p.CKA_TOKEN, True), (p.CKA_PRIVATE, False), (p.CKA_ID, identity),
                           (p.CKA_LABEL, "gateway-signing"), (p.CKA_VERIFY, True),
                           (p.CKA_EC_PARAMS, tuple(bytes.fromhex("06052b81040022")))]
        private_template = [(p.CKA_TOKEN, True), (p.CKA_PRIVATE, True), (p.CKA_ID, identity),
                            (p.CKA_LABEL, "gateway-signing"), (p.CKA_SIGN, True),
                            (p.CKA_DERIVE, False), (p.CKA_DECRYPT, False), (p.CKA_UNWRAP, False),
                            (p.CKA_SENSITIVE, True), (p.CKA_EXTRACTABLE, False),
                            (p.CKA_COPYABLE, (0,)), (p.CKA_MODIFIABLE, False)]
        public_handle, private_handle = session.generateKeyPair(public_template, private_template,
                                                               p.Mechanism(p.CKM_EC_KEY_PAIR_GEN, None))
        public = public_key(session, public_handle)
        pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        assert args.public_output is not None
        args.public_output.write_bytes(pem)
        der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        print(json.dumps({"generated": True, "label": credentials["label"], "keyIdHex": "01",
                          "publicSPKISha256": hashlib.sha256(der).hexdigest(),
                          "privateTemplate": [{"attribute": p.CKA[name], "value": value}
                                              for name, value in private_template]}))
        session.logout()
        session.closeSession()
        return
    private_handles = session.findObjects([(p.CKA_CLASS, p.CKO_PRIVATE_KEY), (p.CKA_ID, identity)])
    public_handles = session.findObjects([(p.CKA_CLASS, p.CKO_PUBLIC_KEY), (p.CKA_ID, identity)])
    assert len(private_handles) == len(public_handles) == 1
    assert len(session.findObjects([(p.CKA_CLASS, p.CKO_PRIVATE_KEY)])) == 1
    private_handle, public_handle = private_handles[0], public_handles[0]
    attributes = [p.CKA_SENSITIVE, p.CKA_ALWAYS_SENSITIVE, p.CKA_EXTRACTABLE, p.CKA_NEVER_EXTRACTABLE,
                  p.CKA_COPYABLE, p.CKA_MODIFIABLE, p.CKA_SIGN, p.CKA_DERIVE, p.CKA_DECRYPT,
                  p.CKA_UNWRAP, p.CKA_TOKEN, p.CKA_PRIVATE, p.CKA_LOCAL, p.CKA_KEY_TYPE]
    values = session.getAttributeValue(private_handle, attributes, allAsBinary=True)
    attribute_records = {p.CKA[name]: (int.from_bytes(bytes(value), "little") if name == p.CKA_KEY_TYPE
                                      else bytes(value) == b"\x01")
                         for name, value in zip(attributes, values)}
    results = []

    def attempt(name, operation):
        try:
            value = operation()
            results.append({"operation": name, "returnCode": 0,
                            "returnedBytes": len(value) if hasattr(value, "__len__") else None})
        except p.PyKCS11Error as error:
            results.append({"operation": name, "returnCode": error.value, "error": str(error)})

    def read_private_value():
        template = p.LowLevel.ckattrlist(1)
        template[0].SetType(p.CKA_VALUE)
        code = session.lib.C_GetAttributeValue(session.session, private_handle, template)
        if code != p.CKR_OK:
            raise p.PyKCS11Error(code)
        return None

    def copy_private_key():
        function_names = ["C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList", "C_GetSlotList",
                          "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList", "C_GetMechanismInfo",
                          "C_InitToken", "C_InitPIN", "C_SetPIN", "C_OpenSession", "C_CloseSession",
                          "C_CloseAllSessions", "C_GetSessionInfo", "C_GetOperationState", "C_SetOperationState",
                          "C_Login", "C_Logout", "C_CreateObject", "C_CopyObject", "C_DestroyObject",
                          "C_GetObjectSize", "C_GetAttributeValue", "C_SetAttributeValue", "C_FindObjectsInit",
                          "C_FindObjects", "C_FindObjectsFinal"]

        class FunctionList(ctypes.Structure):
            _fields_ = [("version", ctypes.c_ubyte * 2)] + [(name, ctypes.c_void_p) for name in function_names]

        class Attribute(ctypes.Structure):
            _fields_ = [("type", ctypes.c_ulong), ("value", ctypes.c_void_p), ("length", ctypes.c_ulong)]

        module = ctypes.CDLL(args.module)
        functions = ctypes.POINTER(FunctionList)()
        module.C_GetFunctionList.argtypes = [ctypes.POINTER(ctypes.POINTER(FunctionList))]
        module.C_GetFunctionList.restype = ctypes.c_ulong
        code = module.C_GetFunctionList(ctypes.byref(functions))
        if code != p.CKR_OK:
            raise p.PyKCS11Error(code)
        def function(name, *argument_types):
            return ctypes.CFUNCTYPE(ctypes.c_ulong, *argument_types)(getattr(functions.contents, name))

        def checked(code):
            if code != p.CKR_OK:
                raise p.PyKCS11Error(code)

        checked(function("C_Initialize", ctypes.c_void_p)(None))
        count = ctypes.c_ulong()
        get_slots = function("C_GetSlotList", ctypes.c_ubyte, ctypes.POINTER(ctypes.c_ulong),
                             ctypes.POINTER(ctypes.c_ulong))
        checked(get_slots(1, None, ctypes.byref(count)))
        slots = (ctypes.c_ulong * count.value)()
        checked(get_slots(1, slots, ctypes.byref(count)))
        assert count.value == 1
        own_session = ctypes.c_ulong()
        checked(function("C_OpenSession", ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))(
                             slots[0], p.CKF_SERIAL_SESSION | p.CKF_RW_SESSION, None, None, ctypes.byref(own_session)))
        pin = credentials["pin"].encode()
        checked(function("C_Login", ctypes.c_ulong, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong)(
            own_session, p.CKU_USER, pin, len(pin)))
        key_class, key_id = ctypes.c_ulong(p.CKO_PRIVATE_KEY), ctypes.c_ubyte(1)
        search = (Attribute * 2)(Attribute(p.CKA_CLASS, ctypes.cast(ctypes.byref(key_class), ctypes.c_void_p),
                                          ctypes.sizeof(key_class)),
                                 Attribute(p.CKA_ID, ctypes.cast(ctypes.byref(key_id), ctypes.c_void_p), 1))
        checked(function("C_FindObjectsInit", ctypes.c_ulong, ctypes.POINTER(Attribute), ctypes.c_ulong)(
            own_session, search, 2))
        found = (ctypes.c_ulong * 2)()
        count = ctypes.c_ulong()
        checked(function("C_FindObjects", ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong,
                         ctypes.POINTER(ctypes.c_ulong))(own_session, found, 2, ctypes.byref(count)))
        checked(function("C_FindObjectsFinal", ctypes.c_ulong)(own_session))
        assert count.value == 1
        call = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
                               ctypes.POINTER(Attribute), ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong))(
                                   functions.contents.C_CopyObject)
        label = ctypes.create_string_buffer(b"copied-key")
        attribute = Attribute(p.CKA_LABEL, ctypes.cast(label, ctypes.c_void_p), 10)
        handle = ctypes.c_ulong()
        code = call(own_session, found[0], ctypes.byref(attribute), 1, ctypes.byref(handle))
        checked(function("C_Logout", ctypes.c_ulong)(own_session))
        checked(function("C_CloseSession", ctypes.c_ulong)(own_session))
        checked(function("C_Finalize", ctypes.c_void_p)(None))
        if code != p.CKR_OK:
            raise p.PyKCS11Error(code)
        return None

    attempt("read-private-value", read_private_value)
    attempt("make-extractable", lambda: session.setAttributeValue(private_handle, [(p.CKA_EXTRACTABLE, True)]))
    attempt("make-nonsensitive", lambda: session.setAttributeValue(private_handle, [(p.CKA_SENSITIVE, False)]))
    wrapping = session.generateKey([(p.CKA_CLASS, p.CKO_SECRET_KEY), (p.CKA_KEY_TYPE, p.CKK_AES),
                                    (p.CKA_VALUE_LEN, 32), (p.CKA_TOKEN, False), (p.CKA_WRAP, True)],
                                   p.Mechanism(p.CKM_AES_KEY_GEN, None))
    attempt("wrap-private-key", lambda: session.wrapKey(wrapping, private_handle,
                                                       p.Mechanism(p.CKM_AES_CBC, bytes(16))))
    challenge = b"TDN v3.1 non-exportable token signing check"
    digest = hashlib.sha384(challenge).digest()
    signature = bytes(session.sign(private_handle, digest, p.Mechanism(p.CKM_ECDSA, None)))
    assert len(signature) == 96
    der_signature = utils.encode_dss_signature(int.from_bytes(signature[:48], "big"),
                                             int.from_bytes(signature[48:], "big"))
    public = public_key(session, public_handle)
    public.verify(der_signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA384())))
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    certificate_bytes = Path("/etc/swanctl/x509/cert.pem").read_bytes()
    certificate = x509.load_pem_x509_certificate(certificate_bytes)
    certificate_public = certificate.public_key().public_bytes(serialization.Encoding.DER,
                                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    assert certificate_public == der
    mechanisms = [str(value) for value in library.getMechanismList(slot)]
    session.logout()
    attempt("wrong-pin-login", lambda: session.login(credentials["pin"] + "-wrong"))
    session.closeSession()
    attempt("copy-private-key", copy_private_key)
    session = library.openSession(slot, p.CKF_SERIAL_SESSION | p.CKF_RW_SESSION)
    session.login(credentials["pin"])
    private_handles = session.findObjects([(p.CKA_CLASS, p.CKO_PRIVATE_KEY)])
    assert len(private_handles) == 1
    after = session.getAttributeValue(private_handles[0], attributes, allAsBinary=True)
    assert [bytes(value) for value in after] == [bytes(value) for value in values]
    session.logout()
    session.closeSession()
    print(json.dumps({"label": credentials["label"], "keyIdHex": "01", "attributes": attribute_records,
                      "mechanisms": mechanisms, "attempts": results, "signatureVerified": True,
                      "challengeHex": challenge.hex(), "signatureHex": signature.hex(),
                      "certificateSha256": hashlib.sha256(certificate_bytes).hexdigest(),
                      "certificateSPKIMatches": True, "privateKeyCountBeforeAndAfter": [1, 1],
                      "attributesUnchanged": True, "tokenSerial": library.getTokenInfo(slot).serialNumber,
                      "publicSPKISha256": hashlib.sha256(der).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()

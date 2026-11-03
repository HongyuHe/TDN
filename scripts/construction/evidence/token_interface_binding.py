#!/usr/bin/env python3
"""Bind token backend versions and a v3 call to observed binaries and keys."""

import argparse
import hashlib
import json
from pathlib import Path

from token_extra_operations import c, p, x509, hashes, serialization, ec, utils
from token_extra_operations import U, P, Functions, Functions3, Interface, Information, Version, Attribute, Mechanism


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True)
    parser.add_argument("--credentials", type=Path)
    args = parser.parse_args()
    module = c.CDLL(args.module)
    functions = c.POINTER(Functions)()
    module.C_GetFunctionList.argtypes = [c.POINTER(c.POINTER(Functions))]
    module.C_GetFunctionList.restype = U
    assert module.C_GetFunctionList(c.byref(functions)) == 0
    legacy_version = list(functions.contents.version)
    if args.credentials:
        interface = c.POINTER(Interface)()
        version = Version(3, 0)
        module.C_GetInterface.argtypes = [c.c_char_p, c.POINTER(Version), c.POINTER(c.POINTER(Interface)), U]
        module.C_GetInterface.restype = U
        assert module.C_GetInterface(b"PKCS 11", c.byref(version), c.byref(interface), 0) == 0
        functions = c.cast(interface.contents.functions, c.POINTER(Functions3))
    operations = []

    def call(name, types, arguments, required=False):
        code = c.CFUNCTYPE(U, *types)(getattr(functions.contents, "C_" + name))(*arguments)
        operations.append({"operation": "C_" + name, "returnCode": code})
        if required:
            assert code == 0, "Required API setup failed: " + name + ": " + str(code)
        return code

    call("Initialize", [P], [None], True)
    info = Information()
    call("GetInfo", [c.POINTER(Information)], [c.byref(info)], True)
    result = {"module": args.module, "moduleSha256": hashlib.sha256(Path(args.module).read_bytes()).hexdigest(),
              "legacyFunctionListVersion": legacy_version, "selectedFunctionListVersion": list(functions.contents.version),
              "cryptokiVersion": [info.cryptokiVersion.major, info.cryptokiVersion.minor],
              "libraryVersion": [info.libraryVersion.major, info.libraryVersion.minor],
              "manufacturer": bytes(info.manufacturer).decode().strip(), "description": bytes(info.description).decode().strip()}
    if args.credentials:
        credentials = json.loads(args.credentials.read_text())
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
        challenge = hashlib.sha384(b"TDN v3.1 interface-version key binding").digest()
        signature = (c.c_ubyte * 128)()
        length = U(128)
        call("Sign", [U, c.c_char_p, U, P, c.POINTER(U)],
             [session, challenge, len(challenge), signature, c.byref(length)], True)
        signed = bytes(signature[:length.value])
        assert len(signed) == 96
        certificate_bytes = Path("/etc/swanctl/x509/cert.pem").read_bytes()
        public = x509.load_pem_x509_certificate(certificate_bytes).public_key()
        der = utils.encode_dss_signature(int.from_bytes(signed[:48], "big"), int.from_bytes(signed[48:], "big"))
        public.verify(der, challenge, ec.ECDSA(utils.Prehashed(hashes.SHA384())))
        code = call("MessageSignInit", [U, c.POINTER(Mechanism), U], [session, c.byref(mechanism), key])
        result.update(label=credentials["label"], keyIdHex="01", messageSignInitCode=code, signatureVerified=True,
                      certificateSha256=hashlib.sha256(certificate_bytes).hexdigest(), challengeDigestHex=challenge.hex(),
                      signatureHex=signed.hex(), publicSPKISha256=hashlib.sha256(public.public_bytes(
                          serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest())
        call("Logout", [U], [session], True)
        call("CloseSession", [U], [session], True)
    call("Finalize", [P], [None], True)
    result["operations"] = operations
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

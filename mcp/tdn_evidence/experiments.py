"""Select the parser for each explicitly configured public experiment."""
from . import mixed


def adapter(name):
    if name == "l2-filter-admission-v1":
        from . import l2_admission
        return l2_admission
    if name == "pkcs11-token-binding-v1":
        from . import key_token_binding
        return key_token_binding
    if name == "pkcs11-token-extra-v1":
        from . import key_token_extra
        return key_token_extra
    if name == "pkcs11-token-boundary-v1":
        from . import key_token
        return key_token
    if name == "key-interface-audit-v1":
        from . import key_access
        return key_access
    if name == "os-provider-identity-v1":
        from . import diversity
        return diversity
    if name == "guest-clock-use-v1":
        from . import clock
        return clock
    if name == "mixed-packet-sizing-v1":
        from . import mixed_sizing
        return mixed_sizing
    if name == "mixed-protocol-v1":
        return mixed
    if name == "eap-correlation-v1":
        from . import eap
        return eap
    if name == "eap-public-v1":
        from . import eap_public
        return eap_public
    if name == "eap-mka-public-v1":
        from . import eap_mka
        return eap_mka
    if name == "native-component-audit-v1":
        from . import native_audit
        return native_audit
    if name == "cover-sender-v1":
        from . import cover
        return cover
    if name == "administration-lifecycle-v1":
        from . import admin_lifecycle
        return admin_lifecycle
    if name == "administration-observations-v1":
        from . import administration
        return administration
    if name == "management-session-v1":
        from . import management
        return management
    if name == "native-ipsec-correlation-v1":
        from . import native_keys
        return native_keys
    if name == "native-packet-sizing-v1":
        from . import sizing
        return sizing
    raise ValueError("Unsupported saved experiment parser: " + name)

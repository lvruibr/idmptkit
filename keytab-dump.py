#!/usr/bin/env python3

from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der.encoder import encode
import argparse
import ssl
from ldap3 import Server, Connection, SASL, GSSAPI, Tls
from ldap3.core.exceptions import LDAPException
from pyasn1.codec.ber.decoder import decode
import struct
import time

KEYTAB_GET_OID = "2.16.840.1.113730.3.8.10.5"


class EncryptionKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'keytype',
            univ.Integer().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        ),
        namedtype.NamedType(
            'keyvalue',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
        )
    )


class KrbSalt(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'type',
            univ.Integer().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        ),
        namedtype.NamedType(
            'salt',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
        )
    )


class KrbKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'key',
            EncryptionKey().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        ),
        namedtype.OptionalNamedType(
            'salt',
            KrbSalt().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
        ),
        namedtype.OptionalNamedType(
            's2kparams',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
            )
        )
    )


class KrbKeyList(univ.SequenceOf):
    componentType = KrbKey()


class CurrentKeys(univ.Sequence):
    """CurrentKeys choice structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'serviceIdentity',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    0
                )
            )
        )
    )


class NewKeys(univ.Sequence):
    """NewKeys choice structure, placeholder."""

    componentType = namedtype.NamedTypes()


class Reply(univ.Sequence):
    """Reply choice structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('new_kvno', univ.Integer()),
        namedtype.NamedType('keys', KrbKeyList())
    )


class GetKeytabControl(univ.Choice):
    """GetKeytabControl structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'newkeys',
            NewKeys().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    0
                )
            )
        ),
        namedtype.NamedType(
            'curkeys',
            CurrentKeys().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    1
                )
            )
        ),
        namedtype.NamedType(
            'reply',
            Reply().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    2
                )
            )
        )
    )


def connect(server: str, username: str = "", password: str = "", krb_auth: bool = False) -> Connection:
    """Establish an LDAP bind.
    :param server: server to connect to.
    :param username: username to use in the LDAP bind, leave empty for anonymous bind.
    :param password: password to use in the LDAP bind, leave empty for anonymous bind.
    :param krb_auth: use Kerberos authentication instead of plaintext.
    :return: connection."""

    tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    server = Server(server, port=636, use_ssl=True, tls=tls_config, get_info='ALL')

    if krb_auth:
        conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI)
    elif username.split(",")[0] != "uid=" and password != "":
        conn = Connection(server, user=username, password=password)
    else:
        conn = Connection(server)
    conn.bind()

    return conn


def get_keytab(conn: Connection, payload) -> bytes | None:
    """Get the keytab of an account.
    :param conn: LDAP bind.
    :param payload: request value of the LDAP extended operation.
    :return: result of the LDAP extended operation containing the keys."""

    try:
        result = conn.extended(request_name=KEYTAB_GET_OID, request_value=payload)
        if result:
            keytab_data = conn.result
            print(f"[+] Keys retrieved successfully ({len(keytab_data["controls"][KEYTAB_GET_OID]["value"])} bytes)")
            return keytab_data["controls"][KEYTAB_GET_OID]["value"]
        else:
            print(conn.last_error)
            print(conn.result)
            print("[-] No key returned")
            print(f"[-] Extended operation result: {result}")
            return None

    except LDAPException as e:
        print(f"[-] Keytab retrieval failed: {e}")
        return None


def write_keytab(path: str, principal: str, realm: str, kvno: int, keys: list[tuple[int, bytes]]):
    """Write a keytab file (version 5.2).
    :param path: path of the keytab file to write.
    :param principal: principal of the keytab.
    :param realm: realm of the principal.
    :param kvno: KVNO value.
    :param keys: list of tuples containing the encryption type of the key and the key itself."""

    components = principal.split("/")

    with open(path, "wb") as f:
        # Add keytab header
        f.write(b"\x05\x02")

        # Add each key
        for enctype, keyval in keys:
            entry = b""
            entry += struct.pack(">H", len(components))
            entry += struct.pack(">H", len(realm)) + realm.encode()
            for comp in components:
                entry += struct.pack(">H", len(comp)) + comp.encode()
            entry += struct.pack(">I", 1)
            entry += struct.pack(">I", int(time.time()))
            entry += struct.pack("B", kvno & 0xFF)
            entry += struct.pack(">H", enctype)
            entry += struct.pack(">H", len(keyval)) + keyval
            entry += struct.pack(">I", kvno)

            f.write(struct.pack(">i", len(entry)))
            f.write(entry)

    print(f"[+] Keytab written to: {path}")


def main():

    parser = argparse.ArgumentParser(add_help=True, description="Retrieve keytab remotely.")
    parser.add_argument("identity", help="Principal whose keytab should be retrieved.")
    parser.add_argument("-u", "--username", action="store", default="", help="Username to query the realm.")
    parser.add_argument("-p", "--password", action="store", default="", help="Password to query the realm.")
    parser.add_argument("-k", "--kerberos", action="store_true", default=False, help="Use kerberos authentication.")
    parser.add_argument("-d", "--domain", action="store", required=True, help="Domain / realm to query.")
    parser.add_argument("-dc", "--domain-controller", action="store", required=True, help="Server to query.")
    args = parser.parse_args()

    gkc = GetKeytabControl()
    curkeys_value = gkc.getComponentByName('curkeys').clone()
    curkeys_value['serviceIdentity'] = f"{args.identity}@{args.domain.upper()}"
    print(f"[+] Requesting keytab for {args.identity}@{args.domain.upper()}")

    gkc.setComponentByName('curkeys', curkeys_value)
    der_bytes = encode(gkc)
    print(f"[+] DER hex request: {der_bytes.hex()}")

    ldap_realm = "".join([",dc=" + dc for dc in args.domain.split(".")])
    bind_dn = f"uid={args.username},cn=users,cn=accounts{ldap_realm}"
    conn = connect(args.domain_controller, bind_dn, args.password, args.kerberos)
    print(f"[+] Established LDAP bind as {bind_dn}")

    raw_keytab = get_keytab(conn, der_bytes)
    if raw_keytab is not None:
        print(f"[+] BER hex response: {raw_keytab.hex()}")

        reply = Reply().subtype(
            explicitTag=tag.Tag(
                tag.tagClassContext,
                tag.tagFormatConstructed,
                2
            )
        )

        decoded, rest = decode(raw_keytab, asn1Spec=reply)
        keys = []

        print(f"[+] Found {len(decoded['keys'])} keys!")
        for i, key in enumerate(decoded['keys'], 1):
            enc = key['key']
            keys.append((int(enc['keytype']), bytes(enc['keyvalue'])))
            print(f"[*] Encryption type: {enc['keytype']}, Key: {bytes(enc["keyvalue"]).hex()}")

        write_keytab(f"{args.identity.replace("/","_")}.keytab", args.identity, args.domain.upper(), int(decoded['new_kvno']), keys)


if __name__ == "__main__":

    main()

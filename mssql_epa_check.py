#!/usr/bin/env python3
import argparse
import binascii
import contextlib
import random
import string
import sys

from impacket import tds, ntlm


BOLD = "\033[1m"
GREEN = f"\033[92m{BOLD}"
YELLOW = f"\033[93m{BOLD}"
RED = f"\033[91m{BOLD}"
CYAN = f"\033[96m{BOLD}"
RESET = "\033[0m"

EPA_LABELS = {
    "off": f"{RED}[+] Extended Protection: Off - NTLM relay POSSIBLE (Vulnerable){RESET}",
    "allowed": f"{YELLOW}[+] Extended Protection: Allowed - NTLM relay may succeed with NTLMv1 clients (Partially Vulnerable){RESET}",
    "required_cb": f"{GREEN}[+] Extended Protection: Required - CBT enforced, NTLM relay NOT possible (Secure){RESET}",
    "required_sb": f"{GREEN}[+] Extended Protection: Required - SPN enforced, NTLM relay NOT possible (Secure){RESET}",
    "kerberos_no_tls": f"{YELLOW}[!] Extended Protection: Cannot be evaluated with Kerberos when Force Encryption is OFF (MSSQL does not validate Kerberos channel bindings without TLS). Use NTLM auth (omit -k) to determine EPA in this case.{RESET}",
}


DEBUG = False


def debug(msg):
    if DEBUG:
        print(f"{CYAN}[DEBUG]{RESET} {msg}")


class MSSQLEpaTest(tds.MSSQL):

    def get_error_messages(self):
        if not hasattr(self, 'replies') or not self.replies:
            return ""
        messages = []
        for keys in self.replies:
            for key in self.replies[keys]:
                if key['TokenType'] == tds.TDS_ERROR_TOKEN:
                    messages.append(key['MsgText'].decode('utf-16le'))
        return " ".join(messages)

    def epa_login(self, username, password='', domain='', hashes=None,
                  channel_binding_value=None, service='MSSQLSvc', strip_target_service=False):
        if hashes:
            lmhash, nthash = hashes.split(':')
            lmhash = binascii.a2b_hex(lmhash)
            nthash = binascii.a2b_hex(nthash)
        else:
            lmhash = ''
            nthash = ''

        debug(f"[NTLM] preLogin to {self.server}:{self.port}")
        resp = self.preLogin()
        debug(f"[NTLM] preLogin Encryption value = {resp['Encryption']}")

        if resp['Encryption'] in (tds.TDS_ENCRYPT_REQ, tds.TDS_ENCRYPT_OFF):
            debug("[NTLM] Setting up TLS context")
            self.set_tls_context()
        else:
            raise Exception(f"Unsupported encryption: {resp['Encryption']}")

        login = tds.TDS_LOGIN()
        login['HostName'] = ''.join(random.choices(string.ascii_letters, k=8)).encode('utf-16le')
        login['AppName'] = ''.join(random.choices(string.ascii_letters, k=8)).encode('utf-16le')
        login['ServerName'] = self.remoteName.encode('utf-16le')
        login['CltIntName'] = login['AppName']
        login['ClientPID'] = random.randint(0, 1024)
        login['PacketSize'] = self.packetSize
        login['OptionFlags2'] = tds.TDS_INIT_LANG_FATAL | tds.TDS_ODBC_ON | tds.TDS_INTEGRATED_SECURITY_ON

        self.version = ntlm.VERSION()
        self.version["ProductMajorVersion"] = 10
        self.version["ProductMinorVersion"] = 0
        self.version["ProductBuild"] = 20348
        auth = ntlm.getNTLMSSPType1('', '', use_ntlmv2=True, version=self.version)
        login['SSPI'] = auth.getData()
        login['Length'] = len(login.getData())

        debug("[NTLM] Sending TDS_LOGIN7 with NTLMSSP Type 1")
        self.sendTDS(tds.TDS_LOGIN7, login.getData())

        if resp['Encryption'] == tds.TDS_ENCRYPT_OFF:
            debug("[NTLM] Force Encryption OFF: tearing down TLS after LOGIN7")
            self.tlsSocket = None

        debug("[NTLM] Receiving TDS response (NTLMSSP Type 2 challenge)")
        tds_resp = self.recvTDS()
        serverChallenge = tds_resp['Data'][3:]
        debug(f"[NTLM] Server challenge length: {len(serverChallenge)} bytes")

        effective_cb = channel_binding_value
        if effective_cb is None:
            if hasattr(self, 'tlsSocket') and self.tlsSocket:
                effective_cb = self.generate_cbt_from_tls_unique()
                debug(f"[NTLM] Computed CBT from TLS unique: {effective_cb.hex()}")
            else:
                effective_cb = b''
                debug("[NTLM] No TLS, using empty CBT")
        else:
            debug(f"[NTLM] Using injected CBT value (len={len(effective_cb)}): {effective_cb.hex() if effective_cb else '(empty)'}")

        debug(f"[NTLM] service='{service}', strip_target_service={strip_target_service}")

        original_test_case = ntlm.TEST_CASE
        if strip_target_service:
            ntlm.TEST_CASE = True

        try:
            type3, exportedSessionKey = ntlm.getNTLMSSPType3(
                auth, serverChallenge, username, password, domain,
                lmhash, nthash,
                service=service, use_ntlmv2=True,
                channel_binding_value=effective_cb,
                version=self.version,
            )
            type3["MIC"] = b"\x00" * 16
            new_mic = ntlm.hmac_md5(
                exportedSessionKey,
                auth.getData() + ntlm.NTLMAuthChallenge(serverChallenge).getData() + type3.getData(),
            )
            type3["MIC"] = new_mic
        finally:
            ntlm.TEST_CASE = original_test_case

        debug("[NTLM] Sending TDS_SSPI with NTLMSSP Type 3")
        self.sendTDS(tds.TDS_SSPI, type3.getData())
        tds_resp = self.recvTDS()

        self.replies = self.parseReply(tds_resp['Data'])
        success = tds.TDS_LOGINACK_TOKEN in self.replies
        debug(f"[NTLM] Login result: {'SUCCESS' if success else 'FAILED'}")
        if not success:
            errors = self.get_error_messages()
            debug(f"[NTLM] Server error message: {errors!r}")
        return success

    def epa_login_kerberos(self, username, password, domain, kdc_host=None,
                           channel_binding_value=None, spn=None):
        """Kerberos auth with optional CBT manipulation.

        channel_binding_value:
          None        -> use computed CBT from TLS (correct behavior)
          bytes (16)  -> inject as fake CBT (bogus or missing/zeroed)
                         For "missing", pass b"\\x00" * 16 (GSS_C_NO_CHANNEL_BINDINGS)
        spn:
          None        -> impacket auto-builds 'MSSQLSvc/<host>.<domain>:<port>'
          str         -> request TGS for this exact SPN (e.g. 'MSSQLSvc/KantoSQL:1433')
        """
        debug(f"[KRB] Calling impacket kerberosLogin: user={username}, domain={domain}, kdc={kdc_host}")
        if channel_binding_value is None:
            debug("[KRB] CBT mode: AUTO (computed from tls_unique if TLS present)")
        else:
            debug(f"[KRB] CBT mode: INJECT (len={len(channel_binding_value)}): {channel_binding_value.hex() if channel_binding_value else '(empty)'}")

        tgs_param = None
        if spn is not None:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5.types import Principal
            from impacket.krb5 import constants

            debug(f"[KRB] Custom SPN mode: {spn}")

            user_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            debug(f"[KRB] Requesting TGT for {username}@{domain}")
            tgt, cipher, _old_session_key, session_key = getKerberosTGT(
                user_principal, password, domain, '', '', '', kdc_host
            )
            debug("[KRB] TGT obtained")

            server_principal = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            debug(f"[KRB] Requesting TGS for SPN={spn}")
            tgs, cipher, _old_session_key, session_key = getKerberosTGS(
                server_principal, domain, kdc_host, tgt, cipher, session_key
            )
            debug("[KRB] TGS obtained")

            tgs_param = {'KDC_REP': tgs, 'cipher': cipher, 'sessionKey': session_key}

        success = self.kerberosLogin(
            None, username, password, domain,
            hashes=None,
            aesKey='',
            kdcHost=kdc_host,
            TGS=tgs_param,
            useCache=False,
            cbt_fake_value=channel_binding_value,
        )
        debug(f"[KRB] Login result: {'SUCCESS' if success else 'FAILED'}")
        if not success:
            errors = self.get_error_messages()
            debug(f"[KRB] Server error message: {errors!r}")
        return success


def test_connection(host, port, username, password, domain, hashes,
                    channel_binding_value=None, service='MSSQLSvc', strip_target_service=False):
    debug(f"--- NTLM test_connection start: host={host}, cb={channel_binding_value!r}, service={service}, strip={strip_target_service} ---")
    conn = MSSQLEpaTest(host, port, host)
    conn.connect()
    try:
        res = conn.epa_login(
            username=username, password=password, domain=domain, hashes=hashes,
            channel_binding_value=channel_binding_value,
            service=service, strip_target_service=strip_target_service,
        )
        if res:
            return "success"
        errors = conn.get_error_messages()
        if "untrusted domain" in errors:
            return "untrusted_domain"
        if "Login failed" in errors:
            return "login_failed"
        return "other"
    except Exception as e:
        debug(f"[NTLM] Exception: {e!r}")
        return f"error: {e}"
    finally:
        with contextlib.suppress(Exception):
            conn.disconnect()


def test_connection_kerberos(host, port, username, password, domain, kdc_host=None,
                             channel_binding_value=None, spn=None):
    debug(f"--- KRB test_connection start: host={host}, kdc={kdc_host}, cb={channel_binding_value!r}, spn={spn!r} ---")
    conn = MSSQLEpaTest(host, port, host)
    conn.connect()
    try:
        res = conn.epa_login_kerberos(
            username=username, password=password, domain=domain,
            kdc_host=kdc_host, channel_binding_value=channel_binding_value,
            spn=spn,
        )
        if res:
            return "success"
        errors = conn.get_error_messages()
        # NTLM uses "untrusted domain" — Kerberos may use a different string.
        # Keep observation flexible until we have real samples.
        if "untrusted domain" in errors:
            return "untrusted_domain"
        if "Login failed" in errors:
            return "login_failed"
        return "other"
    except Exception as e:
        debug(f"[KRB] Exception: {e!r}")
        return f"error: {e}"
    finally:
        with contextlib.suppress(Exception):
            conn.disconnect()


def check_encryption(host, port):
    debug(f"check_encryption: connecting to {host}:{port}")
    conn = MSSQLEpaTest(host, port, host)
    conn.connect()
    try:
        resp = conn.preLogin()
        debug(f"check_encryption: preLogin Encryption={resp['Encryption']}")
        return resp['Encryption']
    finally:
        with contextlib.suppress(Exception):
            conn.disconnect()


def main():
    global DEBUG
    parser = argparse.ArgumentParser(description="MSSQL Extended Protection (EPA) checker")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("-u", "--user", required=True, help="Username (domain/username)")
    parser.add_argument("-p", "--password", default='', help="Password")
    parser.add_argument("-H", "--hashes", default=None, help="NTLM hashes (LMHASH:NTHASH)")
    parser.add_argument("-k", "--kerberos", action="store_true",
                        help="Use Kerberos authentication (password only for now)")
    parser.add_argument("--dc-ip", default=None,
                        help="KDC host (domain controller IP/FQDN). Defaults to domain if not set")
    parser.add_argument("--spn", default=None,
                        help="Override SPN for Kerberos TGS request "
                             "(e.g. 'MSSQLSvc/KantoSQL:1433'). Use when impacket's "
                             "auto-built SPN is not registered in AD")
    parser.add_argument("--port", type=int, default=1433, help="MSSQL port (default: 1433)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug output (per-step trace)")
    args = parser.parse_args()

    DEBUG = args.debug
    debug(f"args: {vars(args)}")

    if '/' not in args.user:
        print("[!] Username must be in format: domain/username")
        sys.exit(1)

    domain, username = args.user.split('/', 1)

    if not args.password and not args.hashes:
        import getpass
        args.password = getpass.getpass("Password: ")

    if args.kerberos and args.hashes:
        print("[!] Kerberos with hashes is not supported yet (password only for now)")
        sys.exit(1)

    if args.kerberos and not args.password:
        print("[!] Kerberos requires a password (other auth methods not supported yet)")
        sys.exit(1)

    print(f"[*] Target: {args.target}:{args.port}")
    print(f"[*] User: {domain}\\{username}")
    print(f"[*] Auth: {'Kerberos' if args.kerberos else 'NTLM'}")
    if args.kerberos:
        print(f"[*] KDC: {args.dc_ip if args.dc_ip else domain}")

    try:
        enc = check_encryption(args.target, args.port)
    except Exception as e:
        print(f"[-] Failed to connect: {e}")
        sys.exit(1)

    if enc == tds.TDS_ENCRYPT_REQ:
        print(f"{GREEN}[*] Force Encryption: Yes{RESET}")
    elif enc == tds.TDS_ENCRYPT_OFF:
        print(f"{RED}[*] Force Encryption: No{RESET}")
    else:
        print(f"[-] Unsupported encryption setting: {enc}")
        sys.exit(1)

    if args.kerberos:
        check_kerberos(args, domain, username, enc)
    else:
        check_ntlm(args, domain, username, enc)


def check_ntlm(args, domain, username, enc):
    test_args = dict(host=args.target, port=args.port,
                     username=username, password=args.password,
                     domain=domain, hashes=args.hashes)

    if enc == tds.TDS_ENCRYPT_REQ:
        prereq = test_connection(**test_args, channel_binding_value=None)
    else:
        prereq = test_connection(**test_args, channel_binding_value=b'')

    print(f"[*] Prereq check: {prereq}")

    if prereq not in ("success", "login_failed"):
        print("[-] Prereq check failed - verify domain credentials are valid")
        sys.exit(1)

    if enc == tds.TDS_ENCRYPT_REQ:
        print("[*] Testing Channel Binding (CBT)...")

        bogus = test_connection(**test_args, channel_binding_value=b'\xde\xad' * 8)
        print(f"[*]   Bogus CBT: {bogus}")

        if bogus == "untrusted_domain":
            missing = test_connection(**test_args, channel_binding_value=b'')
            print(f"[*]   Missing CBT: {missing}")

            if missing == "untrusted_domain":
                result = "required_cb"
            else:
                result = "allowed"
        else:
            result = "off"
    else:
        print("[*] Testing Service Binding (SPN)...")

        bogus = test_connection(**test_args, service='cifs')
        print(f"[*]   Bogus SPN: {bogus}")

        if bogus == "untrusted_domain":
            missing = test_connection(**test_args, service='', strip_target_service=True)
            print(f"[*]   Missing SPN: {missing}")

            if missing == "untrusted_domain":
                result = "required_sb"
            else:
                result = "allowed"
        else:
            result = "off"

    print()
    print(EPA_LABELS[result])


def check_kerberos(args, domain, username, enc):
    test_args = dict(host=args.target, port=args.port,
                     username=username, password=args.password,
                     domain=domain, kdc_host=args.dc_ip, spn=args.spn)

    # Kerberos + Force Encryption OFF: MSSQL does NOT validate Kerberos channel
    # bindings in this case. Without a working CBT validation path AND without an
    # NTLM-style Service-Binding-in-message (Kerberos has no MsvAvTargetName
    # equivalent — Service Binding is intrinsic to ticket encryption), there is no
    # reliable way to determine EPA over Kerberos here. Bail out with a clear message.
    if enc == tds.TDS_ENCRYPT_OFF:
        print()
        print(EPA_LABELS["kerberos_no_tls"])
        return

    # Force Encryption ON: standard CBT test (bogus + missing).
    prereq = test_connection_kerberos(**test_args, channel_binding_value=None)
    print(f"[*] Prereq check: {prereq}")

    if prereq not in ("success", "login_failed"):
        print("[-] Prereq check failed - verify Kerberos credentials are valid")
        print("    (Run with --debug to see details, including TGT/TGS errors)")
        sys.exit(1)

    print("[*] Testing Channel Binding (CBT)...")

    bogus = test_connection_kerberos(**test_args, channel_binding_value=b'\xde\xad' * 8)
    print(f"[*]   Bogus CBT: {bogus}")

    if bogus == "untrusted_domain":
        missing = test_connection_kerberos(**test_args, channel_binding_value=b'\x00' * 16)
        print(f"[*]   Missing CBT (16 zero bytes / GSS_C_NO_CHANNEL_BINDINGS): {missing}")

        if missing == "untrusted_domain":
            result = "required_cb"
        else:
            result = "allowed"
    else:
        result = "off"

    print()
    print(EPA_LABELS[result])


if __name__ == "__main__":
    main()

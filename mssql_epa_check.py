#!/usr/bin/env python3
import argparse
import binascii
import random
import string
import sys

from impacket import tds, ntlm


BOLD = "\033[1m"
GREEN = f"\033[92m{BOLD}"
YELLOW = f"\033[93m{BOLD}"
RED = f"\033[91m{BOLD}"
RESET = "\033[0m"

EPA_LABELS = {
    "off": f"{RED}[+] Extended Protection: Off - NTLM relay POSSIBLE (Vulnerable){RESET}",
    "allowed": f"{YELLOW}[+] Extended Protection: Allowed - NTLM relay may succeed with NTLMv1 clients (Partially Vulnerable){RESET}",
    "required_cb": f"{GREEN}[+] Extended Protection: Required - CBT enforced, NTLM relay NOT possible (Secure){RESET}",
    "required_sb": f"{GREEN}[+] Extended Protection: Required - SPN enforced, NTLM relay NOT possible (Secure){RESET}",
}


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

        resp = self.preLogin()

        if resp['Encryption'] in (tds.TDS_ENCRYPT_REQ, tds.TDS_ENCRYPT_OFF):
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

        self.sendTDS(tds.TDS_LOGIN7, login.getData())

        if resp['Encryption'] == tds.TDS_ENCRYPT_OFF:
            self.tlsSocket = None

        tds_resp = self.recvTDS()
        serverChallenge = tds_resp['Data'][3:]

        effective_cb = channel_binding_value
        if effective_cb is None:
            if hasattr(self, 'tlsSocket') and self.tlsSocket:
                effective_cb = self.generate_cbt_from_tls_unique()
            else:
                effective_cb = b''

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

        self.sendTDS(tds.TDS_SSPI, type3.getData())
        tds_resp = self.recvTDS()

        self.replies = self.parseReply(tds_resp['Data'])
        return tds.TDS_LOGINACK_TOKEN in self.replies


def test_connection(host, port, username, password, domain, hashes,
                    channel_binding_value=None, service='MSSQLSvc', strip_target_service=False):
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
        return f"error: {e}"
    finally:
        try:
            conn.disconnect()
        except:
            pass


def check_encryption(host, port):
    conn = MSSQLEpaTest(host, port, host)
    conn.connect()
    try:
        resp = conn.preLogin()
        return resp['Encryption']
    finally:
        try:
            conn.disconnect()
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="MSSQL Extended Protection (EPA) checker")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("-u", "--user", required=True, help="Username (domain/username)")
    parser.add_argument("-p", "--password", default='', help="Password")
    parser.add_argument("-H", "--hashes", default=None, help="NTLM hashes (LMHASH:NTHASH)")
    parser.add_argument("--port", type=int, default=1433, help="MSSQL port (default: 1433)")
    args = parser.parse_args()

    if '/' not in args.user:
        print("[!] Username must be in format: domain/username")
        sys.exit(1)

    domain, username = args.user.split('/', 1)

    if not args.password and not args.hashes:
        import getpass
        args.password = getpass.getpass("Password: ")

    print(f"[*] Target: {args.target}:{args.port}")
    print(f"[*] User: {domain}\\{username}")

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


if __name__ == "__main__":
    main()

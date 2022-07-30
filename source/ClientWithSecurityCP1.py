import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        # Random hex key will be generated to prevent playback attack
        request_msg = secrets.token_hex(8)
        s.sendall(convert_int_to_bytes(3))
        s.sendall(convert_int_to_bytes(len(request_msg.encode('utf-8'))))
        s.sendall(bytes(request_msg, 'utf-8'))

        # 4 msg recieve from server
        authentication_msg_len = s.recv(8)
        authentication_msg = s.recv(convert_bytes_to_int(authentication_msg_len))
        server_cert_len = s.recv(8)
        server_cert_raw = s.recv(convert_bytes_to_int(server_cert_len))

        # Get public key from cacsertificate.crt
        file1 = open("auth/cacsertificate.crt", "rb")
        ca_cert_raw = file1.read()
        ca_cert = x509.load_pem_x509_certificate(data=ca_cert_raw, backend= default_backend())
        ca_public_key = ca_cert.public_key()

        # Get server cert
        server_cert = x509.load_pem_x509_certificate(data=server_cert_raw, backend=default_backend())

        # Verified signed certification validated
        ca_public_key.verify(signature=server_cert.signature, data=server_cert.tbs_certificate_bytes, padding=padding.PKCS1v15(), algorithm=server_cert.signature_hash_algorithm)

        try:
            # server cert validated
            assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
            # signed msg decrypted
            server_pub_key = server_cert.public_key()
            server_pub_key.verify(authentication_msg, bytes(request_msg, "utf-8"), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH,), hashes.SHA256(),)

        except:
            print("This does not match")
            s.sendall(convert_int_to_bytes(2))
            return

        while True:
                filename = input("Enter a filename to send (enter -1 to exit):")

                while filename != "-1" and (not pathlib.Path(filename).is_file()):
                    filename = input("Invalid filename. Please try again:")

                if filename == "-1":
                    s.sendall(convert_int_to_bytes(2))
                    break

                filename_bytes = bytes(filename, encoding="utf8")

                # Send the filename
                s.sendall(convert_int_to_bytes(0))
                s.sendall(convert_int_to_bytes(len(filename_bytes)))
                s.sendall(filename_bytes)
                filen = filename.split("/")[-1]
                s.sendall(convert_int_to_bytes(1))

                # Send the file
                with open(filename, mode="rb") as fp:
                    with open(f"send_files_enc/enc_{filen}", mode="wb") as f:
                        while True:
                            data = fp.read(117)
                            if not data:
                                break
                            encrpt_msg = server_pub_key.encrypt(data, padding.PKCS1v15())
                            f.write(encrpt_msg)
                            s.sendall(convert_int_to_bytes(len(encrpt_msg)))
                            s.sendall(encrpt_msg)
                        
                        s.sendall(convert_int_to_bytes(0))
    
            # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

        end_time = time.time()
        print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
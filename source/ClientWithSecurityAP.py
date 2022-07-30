from os import system
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
from zmq import NULL


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
        connection = s.connect_ex((server_address, port))
        if connection != 0:
            print(connection)
            sys.exit()

        print("Connected")

        while True:
            filename = input("Enter a filename to send (enter -1 to exit):")

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:")

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            #Extracting server_private_key (Ks-) from server_private_key.pem
            try:
                with open("auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
                    private_key = serialization.load_pem_private_key(
                        bytes(key_file.read(), encoding="utf8"), password=None
                    )
                    public_key = private_key.public_key()
            except Exception as e:
                print(e)

            

            #Creating arbitrary message
            arb_message = "hello world"

            # Send 3 (int convert to bytes) to the server
            s.sendall(convert_int_to_bytes(3)) #mode 3
            s.sendall(convert_int_to_bytes(len(arb_message))) #M1, sending size of authentication message in bytes
            s.sendall(bytes(arb_message, 'utf-8'))
            
            receive_msg_1 = False
            M1_signed_msg = NULL
            while not receive_msg_1:
                #Receiving M1 of signed message
                M1_signed_msg = s.recv(8)
                receive_msg_1 = True
            #Convert M1 to int to set how many bytes to read M2
            M2_signed_msg_size = convert_bytes_to_int(M1_signed_msg)
            
            receive_msg_2 = False
            signed_msg = NULL
            while not receive_msg_2:
                #Receiving M2 signed_msg
                signed_msg = s.recv(M2_signed_msg_size)
                receive_msg_2 = True

            receive_msg_3 = False
            M1_signed_cert = NULL
            while not receive_msg_3:
                #Receiving M1 of signed cert
                M1_signed_cert = s.recv(8)
                receive_msg_3 = True

            #Convert M1 to int to set how many bytes to read M2
            M2_signed_cert_size = convert_bytes_to_int(M1_signed_cert)
            #Read signed_msg

            receive_msg_4 = False
            signed_cert = NULL
            while not receive_msg_4:
                signed_cert = s.recv(M2_signed_cert_size)
                receive_msg_4 = True

            #Check certificate validity
            assert signed_cert.not_valid_before <= datetime.utcnow() <= signed_cert.not_valid_after      

            #Extract ca's public key (Kca+) from cacsertificate.crt
            #Open cacsertificate.crt file
            cac_f = open("auth/cacsertificate.crt", "rb")
            ca_cert_raw = cac_f.read()
            #Load using x509 method
            ca_cert = x509.load_pem_x509_certificate(
                data=ca_cert_raw, backend=default_backend()
            )
            #get public key (Kca+) from cacsertificate.crt
            ca_public_key = ca_cert.public_key()
            
            #Extract server_public_key (Ks+) from server_signed.crt
            #Load using x509 method
            server_cert = x509.load_pem_x509_certificate(
                data=signed_cert, backend=default_backend()
            )
            #verify server certificate using public key
            ca_public_key.verify(
                signature=server_cert.signature, # signature bytes to  verify
                data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
                padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
                algorithm=server_cert.signature_hash_algorithm,
            )
            #Extracting server_public_key (Ks+) from server_signed.crt
            server_public_key = server_cert.public_key()

            #Decrypting signed_msg
            server_public_key.verify(
                signed_msg,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            # Send the filename
            s.sendall(convert_int_to_bytes(0)) #mode
            s.sendall(convert_int_to_bytes(len(filename_bytes))) #M1
            s.sendall(filename_bytes) #M2

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])

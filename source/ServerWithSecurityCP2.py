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


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with open("auth/server_private_key.pem", mode="r", encoding="utf-8") as key_file:
            private_key = serialization.load_pem_private_key(bytes(key_file.read(), encoding="utf-8"), password=None)
            public_key = private_key.public_key()
    except Exception as e:
        print(e)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            filename= "recv_" + filename.split("/")[-1]

                            with open (f"recv_files_enc/enc_{filename}", mode ="wb") as fp:
                                with open(f"recv_files_enc/enc_{filename}", mode="wb") as encf:
                                    while True:
                                        file_length = convert_bytes_to_int(read_bytes(client_socket, 8))
                                        if not file_length:
                                            break
                                        file_data = read_bytes(client_socket, file_length)
                                        print("File is encrypted and written to recv_files_enc")
                                        if not file_data:
                                            break
                                        decryp_msg = private_key.decrypt(file_data, padding.PKCS1v15())
                                        encf.write(file_data)
                                        fp.write(decryp_msg)
                            print(f"Recieved file in {(time.time() - start_time)}s")

                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        
                        case 3:
                            #AP here
                            print("Processing authentication message...")
                            message_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            message = read_bytes(client_socket, message_len)
                            signed_message = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH,), hashes.SHA256(),)
                            print("Currently sending authentication message...")
                            server_file = open("./auth/server_signed.crt", mode = "rb")
                            server_cert = server_file.read()
                            client_socket.sendall(convert_int_to_bytes(len(signed_message)))
                            client_socket.sendall(signed_message)
                            client_socket.sendall(convert_int_to_bytes(len(server_cert)))
                            client_socket.sendall(server_cert)

                        case 4:
                            s_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            sess_key = Fernet(read_bytes(client_socket, s_len))

    except Exception as e:
        print(e)
        s.close()


if __name__ == "__main__":
    main(sys.argv[1:])

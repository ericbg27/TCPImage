import socket
import struct
import imghdr
import os
from argparse import ArgumentParser

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

#import tqdm

HEADER = struct.Struct('!I')
NAME_HEADER = struct.Struct('!H')

ENCRYPTION_SIZE = 256

def create_keys():
    KEY_SIZE = 2048
    pr_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    pb_key = pr_key.public_key()

    return pr_key, pb_key

def receive_size(sock, short=False):
    blocks = []
    if short:
        length = NAME_HEADER.size
    else:
        length = HEADER.size

    while length:
        block = sock.recv(length)
        length -= len(block)
        blocks.append(block)
    
    return b''.join(blocks)

def receive_data_blocks(sock, length, BUFFER_SIZE=4096):
    data = b''
    while length:
        block = sock.recv(BUFFER_SIZE)
        length -= len(block)
        data += block
    
    return data

def receive_data(sock):
    ns = receive_size(sock, short=True)
    (name_size,) = NAME_HEADER.unpack(ns)
    s = receive_size(sock)
    (image_size,) = HEADER.unpack(s)

    name = receive_data_blocks(sock, name_size)
    name = name.decode('ascii')
    image = receive_data_blocks(sock, image_size)
    
    return image, name

if __name__ == "__main__":
    parser = ArgumentParser(description='Transmit an image over TCP')
    parser.add_argument('hostname', nargs='?', default='127.0.0.1',
    help='IP address or hostname (default: %(default)s)')
    parser.add_argument('-p', type=int, metavar='port', default=1060,
    help='TCP port number (default: %(default)s)')
    parser.add_argument('-file_dir', default='', help='Directory in which to save received files (absolute path)')

    args = parser.parse_args()

    if args.file_dir != '':
        cwd = os.getcwd()
        try:
            os.chdir(args.file_dir)
        except:
            print("Could not reach specified path, restoring the current path.")
            os.chdir(cwd)

    host = (args.hostname, args.p)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(host)
    sock.listen(1)

    print('Listening at', sock.getsockname())

    try:
        with open('private_key.pem', 'rb') as key_file:
            pr_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        with open('public_key.pem', 'rb') as key_file:
            pb_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except IOError:
        pr_key, pb_key = create_keys()
    finally:
        pem = pr_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open('private_key.pem', 'wb') as f:
            f.write(pem)
        
        pem_pb = pb_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open('public_key.pem', 'wb') as f:
            f.write(pem_pb)

    pb_key_size = len(pem_pb)

    try:
        while True:
            sc, sockname = sock.accept()
            print('Accepted connection from', sockname)
            sc.send(HEADER.pack(pb_key_size))
            sc.send(pem_pb)

            if sc:
                encrypted_image, name = receive_data(sc)

                image_header = pr_key.decrypt(
                    encrypted_image[0:256],
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                image = image_header + encrypted_image[256:]
                image_type = imghdr.what('', h=image)
                if image_type:
                    n = name.split('.')
                    
                    n[0] += '_server'

                    name = n[0] + '.' + image_type

                    if image:
                        image_file = open(name, 'wb')
                        image_file.write(image)
                        image_file.close()
                else:
                    sc.send('Received file is not an accepted image type'.encode('ascii'))
    except KeyboardInterrupt:
        print('\nClosing Server...')
        sock.close()

        try:
            sc.close()
        except NameError:
            pass
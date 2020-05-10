import socket
import struct
import imghdr
import os
import threading
from argparse import ArgumentParser
from _thread import start_new_thread

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from filter_operator import Operator
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
    cs = receive_size(sock, short=True)
    (command_size,) = NAME_HEADER.unpack(cs)
    s = receive_size(sock)
    (image_size,) = HEADER.unpack(s)

    header = receive_data_blocks(sock, name_size+command_size)
    header = header.decode('ascii')

    name = header[0:name_size]
    command = header[name_size:]

    image = receive_data_blocks(sock, image_size)
    
    return image, name, command

def server_thread(sc, ids, pb_key_size, pem_pb):
    if sc:
        print('Running main thread')
        sc.send(HEADER.pack(pb_key_size))
        sc.send(pem_pb)
        encrypted_image, name, command = receive_data(sc)

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
        CODES = [1, -1]
        if image_type:
            if image:
                n = name.split('.')
                if command != 'None':
                    o = Operator()

                    image = o.operate(command, image)

                    n[0] += '_server_' + command
                else:
                    n[0] += '_server'

                range_start = 10**4
                range_end = 10**5 - 1

                im_id = next(iter(set(range(range_start, range_end)) - ids))

                ids.add(im_id)

                n[0] += '_' + str(im_id)

                name = n[0] + '.' + image_type

                image_file = open(name, 'wb')
                image_file.write(image)
                image_file.close()
                sc.send(str(CODES[0]).encode('ascii'))
        else:
            sc.send(str(CODES[1]).encode('ascii'))

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

    ids = set()

    for filename in os.listdir(os.getcwd()):
        names = filename.split('.')
        if names[-1] == 'jpg' or names[-1] == 'jpeg':
            names = names[0].split('_')
            if isinstance(names[-1], int):
                identifier = names[-1]
                ids.add(int(identifier))

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
            #sc.send(HEADER.pack(pb_key_size))
            #sc.send(pem_pb)

            start_new_thread(server_thread, (sc, ids, pb_key_size, pem_pb))

            
    except KeyboardInterrupt:
        print('\nClosing Server...')
        sock.close()

        try:
            sc.close()
        except NameError:
            pass
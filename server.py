import socket
import struct
import imghdr
import os
import threading
import ssl
from argparse import ArgumentParser
from _thread import start_new_thread

from filter_operator import Operator
#import tqdm

HEADER = struct.Struct('!I')
NAME_HEADER = struct.Struct('!H')

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

def server_thread(sc, ids):
    if sc:
        print('Running main thread')

        image, name, command = receive_data(sc)

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
    parser.add_argument('-a', metavar='cafile', default=None, help='authority: path to CA certificate PEM file')
    parser.add_argument('-s', metavar='certfile', default=None, help='run as server: path to server PEM file')

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

    purpose = ssl.Purpose.CLIENT_AUTH
    context = ssl.create_default_context(purpose, cafile=args.a)
    
    if args.s:
        context.load_cert_chain(args.s)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(host)
    sock.listen(1)

    print('Listening at', sock.getsockname())

    try:
        while True:
            sc, sockname = sock.accept()
            print('Accepted connection from', sockname)
            ssl_sock = context.wrap_socket(sc, server_side=True)

            start_new_thread(server_thread, (ssl_sock, ids))

            
    except KeyboardInterrupt:
        print('\nClosing Server...')
        sock.close()

        try:
            sc.close()
        except NameError:
            pass
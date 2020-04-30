import socket
import struct
from argparse import ArgumentParser

#import tqdm

HEADER = struct.Struct('!I')

def receive_image_size(sock):
    blocks = []
    length = HEADER.size
    while length:
        block = sock.recv(length)
        length -= len(block)
        blocks.append(block)
    
    return b''.join(blocks)

def receive_name(sock):
    NAME_SIZE = 100
    name = sock.recv(NAME_SIZE)

    return name.decode('ascii')

def receive_image(sock):
    s = receive_image_size(sock)
    name = receive_name(sock)
    (image_size,) = HEADER.unpack(s)

    BUFFER_SIZE = 4096
    image = b''
    while image_size:
        block = sock.recv(BUFFER_SIZE)
        image_size -= len(block)
        image += block
    
    return image, name

if __name__ == "__main__":
    parser = ArgumentParser(description='Transmit an image over TCP')
    parser.add_argument('hostname', nargs='?', default='127.0.0.1',
    help='IP address or hostname (default: %(default)s)')
    parser.add_argument('-p', type=int, metavar='port', default=1060,
    help='TCP port number (default: %(default)s)')

    args = parser.parse_args()

    host = (args.hostname, args.p)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(host)
    sock.listen(1)

    print('Listening at', sock.getsockname())

    try:
        while True:
            sc, sockname = sock.accept()
            print('Accepted connection from', sockname)
            sc.shutdown(socket.SHUT_WR)

            if sc:
                image, name = receive_image(sc)
                n = name.split('.')
                
                n[0] += '_server'

                name = n[0] + '.' + n[1]

                if image:
                    image_file = open(name, 'wb')
                    image_file.write(image)
                    image_file.close()
    except KeyboardInterrupt as e:
        print('\nClosing Server...')
        sc.close()
        sock.close()
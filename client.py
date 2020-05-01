import socket, struct
from argparse import ArgumentParser
import time

import tqdm

HEADER = struct.Struct('!I')

BUFFER_SIZE = 4096

def send_image(test_image, sock, image_name):
    byte_image = test_image.read()
    image_size = len(byte_image)

    name_size = len(image_name)

    sock.send(HEADER.pack(name_size))
    sock.send(image_name.encode('ascii'))

    sock.send(HEADER.pack(image_size))

    sent = 0
    remaining = image_size

    progress = tqdm.tqdm(range(image_size), f"Sending image", unit='B', unit_scale=True, unit_divisor=1024, mininterval=0, miniters=1, leave=True)

    for _ in progress:
        if sent >= image_size:
            progress.update(sent)
            break

        if remaining >= BUFFER_SIZE:
            sock.send(byte_image[sent:sent+BUFFER_SIZE])
            sent += BUFFER_SIZE
            remaining -= BUFFER_SIZE
            progress.update(sent)
        else:
            sock.send(byte_image[sent:])
            sent += remaining
            progress.update(sent)
        
        time.sleep(0.01)

    return image_size

if __name__ == "__main__":
    parser = ArgumentParser(description='Transmit an image over TCP')
    parser.add_argument('hostname', nargs='?', default='127.0.0.1',
    help='IP address or hostname (default: %(default)s)')
    parser.add_argument('-p', type=int, metavar='port', default=1060,
    help='TCP port number (default: %(default)s)')
    parser.add_argument('image', type=str, help='Image name')

    args = parser.parse_args()
    test_image = open(args.image, 'rb')

    sock = socket.socket(socket.AF_INET, socket.SOL_SOCKET)
    server = (args.hostname, args.p)
    sock.connect(server)
    #sock.shutdown(socket.SHUT_RD)

    size = send_image(test_image, sock, args.image)

    print('Image with size {} sent'.format(size))

    sock.settimeout(10)

    try:
        msg = sock.recv(128)
        print(msg.decode('ascii'))
    except socket.timeout as e:
        print('Image received without errors.')

    test_image.close()
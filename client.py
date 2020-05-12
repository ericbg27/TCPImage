'''
Only works for JPEG image files
'''
import socket, struct
import time
import ssl
from argparse import ArgumentParser

import tqdm

HEADER = struct.Struct('!I')
NAME_HEADER = struct.Struct('!H')

BUFFER_SIZE = 4096

def send_image(byte_image, sock, image_name, image_command):
    image_size = len(byte_image)

    name_size = len(image_name)

    command_size = len(image_command)

    sock.send(NAME_HEADER.pack(name_size))
    sock.send(NAME_HEADER.pack(command_size))
    sock.send(HEADER.pack(image_size))

    header_str = image_name + image_command
    sock.send(header_str.encode('ascii'))

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
    parser.add_argument('-command', type=str, default='None', help='Image effect to be applied')
    parser.add_argument('-a', metavar='cafile', default=None, help='authority: path to CA certificate PEM file')

    args = parser.parse_args()
    image = open(args.image, 'rb')

    purpose = ssl.Purpose.SERVER_AUTH
    context = ssl.create_default_context(purpose, cafile=args.a)

    sock = socket.socket(socket.AF_INET, socket.SOL_SOCKET)
    server = (args.hostname, args.p)
    sock.connect(server)
    ssl_sock = context.wrap_socket(sock, server_hostname=server[0])

    commands = ['gaussian_filter', 'median_filtering', 'averaging', 'laplacian']
    if args.command not in commands:
        print("Unknown image command, setting default (No command)")
        command = 'None'
    else:
        command = args.command
    size = send_image(image.read(), ssl_sock, args.image, command)

    print('Image with size {} sent'.format(size))

    ssl_sock.settimeout(10)

    CODES = [1, -1]
    try:
        msg = ssl_sock.recv(32)
        code = msg.decode('ascii')
        if int(code) == CODES[0]:
            print('Image received without errors')
        elif int(code) == CODES[1]:
            print('Received file is not an accepted image type')
    except socket.timeout as e:
        pass

    image.close()
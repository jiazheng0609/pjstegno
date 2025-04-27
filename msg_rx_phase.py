import sysv_ipc
import time
import numpy as np
from math import ceil, floor
import sys
import hashlib
import logging
import g711


def roundup(x: float, base: int = 1) -> int:
    return int(ceil(x / base)) * base

def reshape_bits(payload, num_lsb):
    """
    Interleave the bytes of payload into the num_lsb LSBs of carrier.

    :param payload: secret payload
    :param num_lsb: number of least significant bits to use
    :return: Bits arranged
    """
    plen = len(payload)
    bit_height = roundup(plen * 8 / num_lsb)

    payload_bits = np.zeros(shape=(plen, 8), dtype=np.uint8)
    payload_bits[:plen, :] = np.unpackbits(np.frombuffer(payload, dtype=np.uint8, count=plen)).reshape(plen, 8)
    payload_bits.resize(bit_height * num_lsb)
    payload_bits = payload_bits.reshape(bit_height, num_lsb)

    return payload_bits, bit_height

def write_file(filename, rcv_bytes):
    with open(filename, 'wb') as ofile:
        ofile.write(rcv_bytes)

def print_realtime_text(decode_one):
    try:
        text = str(decode_one, "utf-8")
        print(text, end='', flush=True)
    except UnicodeDecodeError:
        pass

def decode(carrier: bytes) -> bytes:
    textLength = 56
    blockLength = 160
    blockMid = blockLength // 2
    # Get header info

    code = g711.decode_ulaw(carrier)
    
    # Get the phase and convert it to binary
    codePhases = np.angle(np.fft.fft(code))[blockMid - textLength:blockMid]
    codeInBinary = (codePhases < 0).astype(np.int16)

    return np.packbits(codeInBinary).tobytes()


def recv_and_extract(secret_len):
    KEY = 81
    logging.info(f"{KEY=}")
    rmq = sysv_ipc.MessageQueue(KEY, flags=sysv_ipc.IPC_CREAT, mode=0o660)
    logging.info(f"{rmq.id=}")
    logging.info("ready to receive messages.")
    start_time = time.time()
    counter = 0
    end_h = 0
    hung_up = 0
    found_start = 0
    print_realtime = 1
    decoded = b''

    try:
        while end_h < secret_len:
            mtext, mtype = rmq.receive(type=1)

            dec_one = decode(mtext)
            #if not found_start:
            #    if b'\x55\xaa' in dec_one:
            #        logging.info("found preamble")
            #        pos = dec_one.find(b'\x55\xaa')
            #        dec_one = dec_one[pos+len(b'\x55\xaa'):]
            #        found_start = 1
            #    else:
            #        logging.info("waiting preamble")
            #        continue

            if print_realtime:
                print_realtime_text(dec_one)
            decoded = decoded + dec_one
            cbit_height = len(dec_one)
            end_h = end_h + cbit_height
            
            end_time = time.time()

            logging.debug(f"{end_time - start_time} {cbit_height} extracted total extract {end_h} byte, {end_h * 8} bit")
    except KeyboardInterrupt:
        pass
    except sysv_ipc.ExistentialError:
        logging.info("phone hung up")
        hung_up = 1
    finally:
        if not hung_up:
            rmq.remove()
            logging.info("queue removed")

    return decoded, end_h

def extract_loop(secret_filename, secret_len):
    logging.basicConfig(level=logging.INFO)
    filename = sys.argv[1]
    start_h = 0
    end_h = 0
    decoded = b''
    secret_byte = bytearray(b'')

    while (end_h < secret_len):
        decoded, end_h = recv_and_extract(secret_len)
        secret_byte.extend(decoded)

    #write_file(filename, secret_byte[:secret_len])
    write_file(filename, secret_byte)
    print("wrote to file:", filename)
    md5val = hashlib.md5(secret_byte[:secret_len]).hexdigest()
    print(f"MD5: {md5val}")




if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} filename size(bytes)")
        exit(1)

    secret_len = int(sys.argv[2])
    extract_loop(sys.argv[1], secret_len)

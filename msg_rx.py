import sysv_ipc
import time
import numpy as np
from math import ceil, floor
import sys


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


def my_lsb_deinterleave_bytes(carrier: bytes, num_lsb: int, byte_depth: int = 1) -> bytes:
    """
    Deinterleave num_bits bits from the num_lsb LSBs of carrier.

    :param carrier: carrier bytes
    :param num_lsb: number of least significant bits to use
    :param byte_depth: byte depth of carrier values
    :return: The deinterleaved bytes
    """

    plen = len(carrier)
    payload_bits = np.unpackbits(np.frombuffer(carrier, dtype=np.uint8, count=byte_depth * plen)
                                 ).reshape(plen, 8 * byte_depth)[:, 8 * byte_depth - num_lsb: 8 * byte_depth]
    return np.packbits(payload_bits).tobytes()


def recv_and_extract(num_lsb, byte_depth, secret_len):
    KEY = 81
    print("KEY:", KEY)
    rmq = sysv_ipc.MessageQueue(KEY, flags=sysv_ipc.IPC_CREAT, mode=0o660)
    print("id:", rmq.id)
    print("ready to receive messages.")
    start_time = time.time()
    counter = 0
    end_h = 0
    hung_up = 0
    found_start = 0
    decoded = b''

    try:
        while end_h < secret_len:
            mtext, mtype = rmq.receive(type=1)

            dec_one = my_lsb_deinterleave_bytes(mtext, num_lsb, byte_depth)
            if not found_start:
                if b'\x55\xaa' in dec_one:
                    print("found preamble")
                    pos = dec_one.find(b'\x55\xaa')
                    dec_one = dec_one[pos+len(b'\x55\xaa'):]
                    found_start = 1
                else:
                    print("waiting preamble")
                    continue

            decoded = decoded + dec_one
            cbit_height = len(dec_one)
            end_h = end_h + cbit_height
            
            end_time = time.time()

            print("firstb %x last %x" % (mtext[0], mtext[-1]))
            print(end_time - start_time, "len", cbit_height, "extracted",
              "total extract", end_h, "byte", end_h * 8, "bit")
    except KeyboardInterrupt:
        pass
    except sysv_ipc.ExistentialError:
        print("phone hung up")
        hung_up = 1
    finally:
        if not hung_up:
            rmq.remove()
            print("queue removed")

    return decoded, end_h

def main():

    filename = sys.argv[1]
    num_lsb = 3
    byte_depth = 1
    start_h = 0
    end_h = 0
    secret_len = int(sys.argv[2])
    decoded = b''
    secret_byte = bytearray(b'')
    extract_sets = secret_len // num_lsb

    while (end_h < secret_len):
        decoded, end_h = recv_and_extract(num_lsb, byte_depth, secret_len)
        secret_byte.extend(decoded)

    write_file(filename, secret_byte[:secret_len])
    print("wrote to file:", filename)



    print("continue to receive until call has ended")
    try:
        while True:
            mtext, mtype = rmq.receive(type=1)
    except KeyboardInterrupt:
        pass
    finally:
        rmq.remove()
        print("queue removed")

if __name__ == '__main__':
    main()

import sysv_ipc
import time
import numpy as np
from math import ceil, floor
import sys
import hashlib

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

def my_lsb_interleave_byte(carrier, payload_bits, num_lsb, bit_height, byte_depth, start_h, end_h):
    """
    Interleave the bytes of payload into the num_lsb LSBs of carrier.

    :param carrier: carrier bytes
    :param byte_depth: byte depth of carrier values
    :return: The interleaved bytes
    """
    carrier_bits = np.unpackbits(np.frombuffer(carrier, dtype=np.uint8, count=byte_depth * bit_height)
                              ).reshape(bit_height, 8 * byte_depth)
    hides = end_h - start_h
    if (hides < len(carrier_bits)):
        carrier_bits[:hides, 8 * byte_depth - num_lsb: 8 * byte_depth] = payload_bits[start_h:end_h]
    else:
        carrier_bits[:, 8 * byte_depth - num_lsb: 8 * byte_depth] = payload_bits[start_h:end_h]
    ret = np.packbits(carrier_bits).tobytes() + carrier[byte_depth * bit_height:]
    return ret

def insert_preamble(payload_bits, payload_sets, num_lsb):
    prefix = bytearray(b'\x55\xaa')
    prefix_bits, prefix_sets = reshape_bits(prefix, num_lsb)
    payload_bits = np.concatenate((prefix_bits, payload_bits), axis=0)
    payload_sets = prefix_sets + payload_sets
    return payload_bits, payload_sets

def recv_and_hide(payload, num_lsb, byte_depth, end_b):
    KEY = 81
    TKEY = 82
    rmq = sysv_ipc.MessageQueue(KEY, flags=sysv_ipc.IPC_CREAT, mode=0o660)
    tmq = sysv_ipc.MessageQueue(TKEY, flags=sysv_ipc.IPC_CREAT, mode=0o660)

    print("rmq id:", rmq.id, "tmq id:", tmq.id)
    print("ready to receive messages.")
    start_time = time.time()
    counter = 0
    hung_up = 0
    prefix = bytearray(b'\x55\xaa')
    end_h_hist = [0, 0, 0]


    if end_b != 0:
        payload = prefix + payload[end_b // 8:] 
    else:
        payload = prefix + payload
    payload_bits, hide_sets = reshape_bits(payload, num_lsb)

    print("total", hide_sets, "sets need to be hidden")

    end_h = end_b // num_lsb 

    try:
        while True:
            mtext, mtype = rmq.receive(type=1)

            cbit_height = len(mtext) // byte_depth
            start_h = end_h
            if ((end_h + cbit_height) < hide_sets):
                end_h = end_h + cbit_height
            else:
                end_h = hide_sets
            ret = my_lsb_interleave_byte(mtext, payload_bits, num_lsb, cbit_height, byte_depth, start_h, end_h)



            tmq.send(ret, block=False, type=1)
            end_h_hist[counter % 3] = end_h
            counter = counter + 1
            end_time = time.time()
            print("carrierlen %d start_h %d end_h %d %d bits %.2f firstb %x last %x" % 
                    (cbit_height, start_h, end_h, end_h * num_lsb,
                    end_h / hide_sets * 100, ret[0], ret[-1]))
            
    except KeyboardInterrupt:
        pass
    except sysv_ipc.ExistentialError:
        print("phone hung up")
        hung_up = 1
    finally:
        if not hung_up:
            rmq.remove()
            tmq.remove()
            print("queue removed")
    return end_h_hist[(counter - 2) % 3] * num_lsb - 16


def inject_loop(secret_filename):
    num_lsb = 3
    byte_depth = 1
    start_b = 0
    end_b = 0

    ifile = open(secret_filename, 'rb')
    filecontent = ifile.read()
    filelen = len(filecontent)
    md5val = hashlib.md5(filecontent).hexdigest()
    print("hiding", secret_filename, filelen, "bytes")

    while end_b < filelen * 8:
        end_b = end_b + recv_and_hide(filecontent, num_lsb, byte_depth, 0)
        print(f"Total {filelen*8} bits,  {end_b} hidden, {end_b/(filelen*8)}")
        filecontent = filecontent[end_b // 8:]

    print(f"{secret_filename} MD5: {md5val}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} filename")
        exit(1)

    inject_loop(sys.argv[1])

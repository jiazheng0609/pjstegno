import sysv_ipc
import time
import numpy as np
import sys
import hashlib
import logging
from abc import ABC, abstractmethod

class PJStegno:
    

    def recv_and_extract(self, decoder, secret_len):
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

                dec_one = decoder.extract(mtext)
                if not found_start:
                    if b'\x55\xaa' in dec_one:
                        logging.info("found preamble")
                        pos = dec_one.find(b'\x55\xaa')
                        dec_one = dec_one[pos+len(b'\x55\xaa'):]
                        found_start = 1
                    else:
                        logging.info("waiting preamble")
                        continue

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


    def extract_loop(self, decoder, filename, secret_len):
        logging.basicConfig(level=logging.DEBUG)
        num_lsb = 3
        byte_depth = 1
        start_h = 0
        end_h = 0
        decoded = b''
        secret_byte = bytearray(b'')
        extract_sets = secret_len // num_lsb

        while (end_h < secret_len):
            decoded, end_h = self.recv_and_extract(decoder, secret_len)
            secret_byte.extend(decoded)

        write_file(filename, secret_byte[:secret_len])
        print("wrote to file:", filename)
        md5val = hashlib.md5(secret_byte[:secret_len]).hexdigest()
        print(f"MD5: {md5val}")

class Decoder(ABC):
    @abstractmethod
    def extract(self):
        return

class LSBDecoder(Decoder):
    def __init__(self, num_lsb: int, byte_depth: int = 1):
        self.num_lsb = num_lsb
        self.byte_depth = byte_depth

    def extract(self, carrier: bytes) -> bytes:
        """
        Deinterleave num_bits bits from the num_lsb LSBs of carrier.

        :param carrier: carrier bytes
        :param num_lsb: number of least significant bits to use
        :param byte_depth: byte depth of carrier values
        :return: The deinterleaved bytes
        """

        plen = len(carrier) // self.byte_depth
        payload_bits = np.unpackbits(np.frombuffer(carrier, dtype=np.uint8, count=self.byte_depth * plen)
                                    ).reshape(plen, 8 * self.byte_depth)[:, 8 * self.byte_depth - self.num_lsb: 8 * self.byte_depth]
        return np.packbits(payload_bits).tobytes()

class QIMDecoder(Decoder):
    def __init__(self, delta):
        self.delta = delta
        
        
    def embed(self, x, m):
        x = x.astype(float)
        d = self.delta
        y = np.round(x / d) * d + (-1) ** (m+1) * d / 4
        return y
    
    def extract(self, carrier: bytes):
        z = np.frombuffer(carrier, dtype=np.int8, count=160)
        m_detected = np.zeros_like(z, dtype=int)

        z0 = self.embed(z, 0)
        z1 = self.embed(z, 1)

        d0 = np.abs(z - z0)
        d1 = np.abs(z - z1)

        gen = zip(range(len(z)), d0, d1)
        for i, dd0, dd1 in gen:
            if dd0 < dd1:
                m_detected[i] = 0
            else:
                m_detected[i] = 1

        
        return np.packbits(m_detected).tobytes()
        


def write_file(filename, rcv_bytes):
    with open(filename, 'wb') as ofile:
        ofile.write(rcv_bytes)

def print_realtime_text(decode_one):
    try:
        text = str(decode_one, "utf-8")
        print(text, end='', flush=True)
    except UnicodeDecodeError:
        pass


if __name__ == '__main__':
    
    receiver = PJStegno()
    #decoder = LSBDecoder(3, 1)
    decoder = QIMDecoder(4)
    receiver.extract_loop(decoder, "output.txt", 10400)
    

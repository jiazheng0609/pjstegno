import sysv_ipc
import time
import numpy as np
from math import ceil, floor
import sys
import hashlib
import logging
from abc import ABC, abstractmethod

class PJStegno:
    def inject_loop(self, encoder, secret_filename):

        start_b = 0
        end_b = 0

        
        ifile = open(secret_filename, 'rb')
        filecontent = ifile.read()
        filelen = len(filecontent)
        md5val = hashlib.md5(filecontent).hexdigest()
        print("hiding", secret_filename, filelen, "bytes")

        while end_b < filelen * 8:
            end_b = end_b + self.recv_and_hide(filecontent, encoder, 0)
            print(f"Total {filelen*8} bits,  {end_b} hidden, {end_b/(filelen*8)}")
            filecontent = filecontent[end_b // 8:]

        print(f"{secret_filename} MD5: {md5val}")

    def recv_and_hide(self, payload, encoder, end_b):
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
        start_h = 0


        if end_b != 0:
            payload = prefix + payload[end_b // 8:] 
        else:
            payload = prefix + payload
        payload_bits, hide_sets = encoder.reshape_bits(payload)

        print("total", hide_sets, "sets need to be hidden")

        end_h = encoder.end_h(end_b)

        try:
            while True:
                mtext, mtype = rmq.receive(type=1)

                cbit_height = encoder.cbit_height(len(mtext))
                start_h = end_h
                if ((end_h + cbit_height) < hide_sets):
                    end_h = end_h + cbit_height
                else:
                    end_h = hide_sets
                ret = encoder.hide(mtext, payload_bits, cbit_height, start_h, end_h)

                tmq.send(ret, block=False, type=1)
                end_h_hist[counter % 3] = end_h
                counter = counter + 1
                end_time = time.time()
                logging.debug("carrierlen %d start_h %d end_h %d %d bits %.2f firstb %x last %x" % 
                        (cbit_height, start_h, end_h, encoder.end_b(end_h),
                        end_h / hide_sets * 100, ret[0], ret[-1]))
                if end_h == hide_sets:
                    break

            logging.info("transmission of secret completed, continue to receive until the phone hung up")

            while True:
                mtext, mtype = rmq.receive(type=1)
                tmq.send(mtext, block=False, type=1)
                
        except KeyboardInterrupt:
            pass
        except sysv_ipc.ExistentialError:
            logging.info("phone hung up")
            hung_up = 1
            if end_h == hide_sets:
                return end_h * num_lsb
            elif end_h > 0:
                return end_h_hist[(counter - 2)% 3] * num_lsb - 16
        finally:
            if not hung_up:
                rmq.remove()
                tmq.remove()
                logging.info("queue removed")
        return end_h * num_lsb

class Encoder(ABC):
    @property
    def cbit_height(self): # how many sets could be hidden in one payload
        return self.cbit_height
    
    @abstractmethod
    def hide(self):
        return
    
    @abstractmethod
    def reshape_bits(self):
        return
    
class LSBEncoder(Encoder):
    def __init__(self, num_lsb, byte_depth):
        self.num_lsb = num_lsb
        self.byte_depth = byte_depth

    def cbit_height(self, payloadlen):
        return payloadlen // self.byte_depth
    
    def end_b(self, end_h):
        return end_h * self.num_lsb
    
    def end_h(self, end_b):
        return end_b // self.num_lsb

    def hide(self, carrier, payload_bits, bit_height, start_h, end_h):
        """
        Interleave the payload bits into the num_lsb LSBs of carrier.

        :param carrier: carrier bytes
        :param payload_bits: bits arranged by reshape_bits()
        :param num_lsb: number of least significant bits to use
        :param byte_depth: byte depth of carrier values
        :param start_h: start point of payload to be hidden
        :param end_h: end point of payload to be hidden
        :return: The interleaved bytes
        """
        carrier_bits = np.unpackbits(np.frombuffer(carrier, dtype=np.uint8, count=self.byte_depth * bit_height)
                                ).reshape(bit_height, 8 * self.byte_depth)
        hides = end_h - start_h
        if (hides < len(carrier_bits)):
            carrier_bits[:hides, 8 * self.byte_depth - self.num_lsb: 8 * self.byte_depth] = payload_bits[start_h:end_h]
        else:
            carrier_bits[:, 8 * self.byte_depth - self.num_lsb: 8 * self.byte_depth] = payload_bits[start_h:end_h]
        ret = np.packbits(carrier_bits).tobytes() + carrier[self.byte_depth * bit_height:]
        return ret
    
    def reshape_bits(self, payload):
        """
        Agrrange payload bytes into groups of lsb bits.
    
        :param payload: secret payload
        :param num_lsb: number of least significant bits to use
        :return: Bits arranged
        """
        plen = len(payload)
        bit_height = self.roundup(plen * 8 / self.num_lsb)

        payload_bits = np.zeros(shape=(plen, 8), dtype=np.uint8)
        payload_bits[:plen, :] = np.unpackbits(np.frombuffer(payload, dtype=np.uint8, count=plen)).reshape(plen, 8)
        payload_bits.resize(bit_height * self.num_lsb)
        payload_bits = payload_bits.reshape(bit_height, self.num_lsb)

        return payload_bits, bit_height

    def roundup(self, x: float) -> int:
        return int(ceil(x))






    

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} filename")
        exit(1)

    logging.basicConfig(level=logging.DEBUG)
    num_lsb = 3
    byte_depth = 1

    receiver = PJStegno()
    encoder = LSBEncoder(num_lsb, byte_depth)
    receiver.inject_loop(encoder, sys.argv[1])
    

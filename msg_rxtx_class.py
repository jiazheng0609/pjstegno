import sysv_ipc
import time
import numpy as np
from math import ceil, floor
import sys
import hashlib
import logging
import g711
from abc import ABC, abstractmethod

class PJStegno:
    def inject_loop(self, encoder, secret_filename):

        end_b = 0

        
        ifile = open(secret_filename, 'rb')
        filecontent = ifile.read()
        filelen = len(filecontent)
        md5val = hashlib.md5(filecontent).hexdigest()
        print("hiding", secret_filename, filelen, "bytes")

        while end_b < filelen * 8:
            end_b = end_b + self.recv_and_hide(filecontent, encoder)
            print(f"Total {filelen*8} bits,  {end_b} hidden, {end_b/(filelen*8)}")
            filecontent = filecontent[end_b // 8:]

        print(f"{secret_filename} MD5: {md5val}")

    def recv_and_hide(self, payload, encoder):
        KEY = 81
        TKEY = 82
        rmq = sysv_ipc.MessageQueue(KEY, flags=sysv_ipc.IPC_CREAT, mode=0o660)
        tmq = sysv_ipc.MessageQueue(TKEY, flags=sysv_ipc.IPC_CREAT, mode=0o660)

        print("rmq id:", rmq.id, "tmq id:", tmq.id)
        start_time = time.time()
        counter = 0
        hung_up = 0
        prefix = bytearray(b'\x55\xaa')
        end_h_hist = [0, 0, 0]
        start_h = 0
        end_h = 0


        
        payload = prefix + payload
        payload_bits, hide_sets = encoder.reshape_bits(payload)

        print("total", hide_sets, "sets need to be hidden")

        

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
                return encoder.end_b(end_h)
            elif end_h > 0:
                return encoder.end_b(end_h_hist[(counter - 2)% 3])  - 16
        finally:
            if not hung_up:
                rmq.remove()
                tmq.remove()
                logging.info("queue removed")
        return encoder.end_b(end_h)

class Encoder(ABC):
    @property
    def cbit_height(self): 
        """how many sets could be hidden in one payload"""
        
        return self.cbit_height
    
    @abstractmethod
    def end_h(self, end_b):
        """convert end_b(end bit) to end_h(end payload set)"""
        return
    
    @abstractmethod
    def end_b(self, end_h):
        """convert end_h(end payload set) to end_b(end bit)"""
        return

    @abstractmethod
    def hide(self, carrier, payload_bits, bit_height, start_h, end_h):
        """
        Interleave the payload bits into a carrier.

        :param carrier: carrier bytes
        :param payload_bits: bits arranged by reshape_bits()
        :param start_h: start point of payload to be hidden
        :param end_h: end point of payload to be hidden
        :return: encoded bytes
        """
        return
    
    @abstractmethod
    def reshape_bits(self):
        """
        Preprocess of secret information. For example: bytes to bits.
        """
        return
    
class LSBEncoder(Encoder):
    def __init__(self, num_lsb, byte_depth):
        """
        :param num_lsb: number of least significant bits to use
        :param byte_depth: byte depth of carrier values
        """
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


class PhaseEncoder(Encoder):
    def __init__(self):
        pass

    def cbit_height(self, payloadlen):
        return 56

    def end_h(self, end_b):
        return end_b

    def end_b(self, end_h):
        return end_h
        
    def reshape_bits(self, payload):
        plen = len(payload)
        payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8, count=plen))
        bitsInPi = payload_bits.astype(np.int64)

        bitsInPi[payload_bits == 0] = -1
        bitsInPi = bitsInPi * -np.pi / 2

        hide_sets = len(bitsInPi)
        return bitsInPi, hide_sets

    def hide(self, carrier, payload_bits, _, start_h, end_h):
        dec_one = g711.decode_ulaw(carrier)
        chunkSize = 160
        numberOfChunks = int(np.ceil(dec_one.shape[0] / chunkSize))
        audioData = dec_one.copy()

        #Breaking the Audio into chunks
        if len(dec_one.shape) == 1:
            audioData.resize(numberOfChunks * chunkSize, refcheck=False)
            audioData = audioData[np.newaxis]
        else:
            audioData.resize((numberOfChunks * chunkSize, audioData.shape[1]), refcheck=False)
            audioData = audioData.T

        chunks = audioData[0].reshape((numberOfChunks, chunkSize))


        #Applying DFT on audio chunks
        chunks = np.fft.fft(chunks)
        magnitudes = np.abs(chunks)
        phases = np.angle(chunks)
        phaseDiff = np.diff(phases, axis=0)


        midChunk = chunkSize // 2
        textLength = end_h - start_h
        print(f"{textLength=} {start_h=} {end_h=}")


        # Phase conversion
        phases[0, midChunk - textLength: midChunk] = payload_bits[start_h:end_h]
        #print(payload_bits[start_h:end_h])
        phases[0, midChunk + 1: midChunk + 1 + textLength] = -payload_bits[start_h:end_h][::-1]

        # Compute the phase matrix
        for i in range(1, len(phases)):
            phases[i] = phases[i - 1] + phaseDiff[i - 1]
            
        # Apply Inverse fourier trnasform after applying phase differences
        chunks = (magnitudes * np.exp(1j * phases))
        chunks = np.fft.ifft(chunks).real
        # Combining all block of audio again
        audioData[0] = chunks.ravel()
        ret = g711.encode_ulaw(audioData)

        return ret


class QIMEncoder(Encoder):
    def __init__(self, delta):
        self.delta = delta

    def cbit_height(self, payloadlen):
        return payloadlen
    
    def end_b(self, end_h):
        return end_h
    
    def end_h(self, end_b):
        return end_b

    def reshape_bits(self, payload):
        plen = len(payload)
        payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8, count=plen))
        payload_bits = payload_bits.astype(np.int8)
        
        return payload_bits, len(payload_bits)
    
    def embed(self, x, m):
        x = x.astype(float)
        d = self.delta
        y = np.round(x / d) * d + (-1) ** (m+1) * d / 4.
        return y
    
    def hide(self, carrier, payload_bits, bit_height, start_h, end_h):
        dec_one = np.frombuffer(carrier, dtype=np.int8, count=160)
        if (end_h - start_h) < bit_height:
            payload1 = payload_bits[start_h:end_h].copy()
            m = np.pad(payload1, (0, bit_height-end_h+start_h), 'constant', constant_values=(0,0))
            m[end_h - start_h:] = 0
        else:
            m = payload_bits[start_h:end_h]

        dec_one = self.embed(dec_one, m)
        ret = bytes(dec_one.astype(np.uint8))
        
        return ret 
    

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} filename")
        exit(1)

    logging.basicConfig(level=logging.DEBUG)
    num_lsb = 3
    byte_depth = 1

    receiver = PJStegno()
    #encoder = LSBEncoder(num_lsb, byte_depth)
    #encoder = PhaseEncoder()
    encoder = QIMEncoder(4)
    receiver.inject_loop(encoder, sys.argv[1])
    

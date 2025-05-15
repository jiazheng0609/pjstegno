import numpy as np
from math import ceil
from pjstegno import Encoder, Decoder

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


class LSBDecoder(Decoder):
    def __init__(self, num_lsb: int, byte_depth: int = 1):
        """
        :param num_lsb: number of least significant bits to use
        :param byte_depth: byte depth of carrier values
        """
        self.num_lsb = num_lsb
        self.byte_depth = byte_depth

    def extract(self, carrier: bytes) -> bytes:
        """
        Deinterleave num_bits bits from the num_lsb LSBs of carrier.

        :param carrier: carrier bytes
        :return: The deinterleaved bytes
        """

        plen = len(carrier) // self.byte_depth
        payload_bits = np.unpackbits(np.frombuffer(carrier, dtype=np.uint8, count=self.byte_depth * plen)
                                    ).reshape(plen, 8 * self.byte_depth)[:, 8 * self.byte_depth - self.num_lsb: 8 * self.byte_depth]
        return np.packbits(payload_bits).tobytes()
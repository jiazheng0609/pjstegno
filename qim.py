from pjstegno import Encoder, Decoder
import numpy as np

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
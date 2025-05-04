import numpy as np
import sys

def reshape_bits(payload):
    plen = len(payload)
    payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8, count=plen))
    
    return payload_bits


def count_ber(bits1, bits2):
    error = 0
    for i in range(len(bits1)):
        if bits1[i] != bits2[i]:
            error = error + 1
    return error, error / len(bits1)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} filename filename")
        exit(1)

    ifile = open(sys.argv[1], 'rb')
    filecontent1 = ifile.read()

    ifile = open(sys.argv[2], 'rb')
    filecontent2 = ifile.read()

    bits1 = reshape_bits(filecontent1)
    bits2 = reshape_bits(filecontent2)

    errors, ber = count_ber(bits1, bits2)

    print(f"{len(bits1)=} {errors=} bit_error_rate={ber}")
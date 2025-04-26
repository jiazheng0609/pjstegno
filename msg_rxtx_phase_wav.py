import sysv_ipc
import time
import numpy as np
from math import ceil, floor
import sys
import hashlib
import logging
import g711
from scipy.io import wavfile

def reshape_bits(payload):
    plen = len(payload)
    payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8, count=plen))
    bitsInPi = payload_bits.astype(np.int64)
    
    bitsInPi[payload_bits == 0] = -1
    bitsInPi = bitsInPi * -np.pi / 2
   
    hide_sets = len(payload_bits)
    return bitsInPi, hide_sets

def hide(carrier, payload_bits, start_h, end_h):
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
    print(payload_bits[start_h:end_h])
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
    
    return ret, audioData[0]

def decode(carrier: bytes) -> bytes:
    textLength = 56
    blockLength = 160
    blockMid = blockLength // 2
    # Get header info

    code = g711.decode_ulaw(carrier)

    # Get the phase and convert it to binary
    codePhases = np.angle(np.fft.fft(code))[blockMid - textLength:blockMid]
    codeInBinary = (codePhases < 0).astype(np.int16)

    # Convert into characters
    codeInIntCode = codeInBinary.reshape((-1, 8)).dot(1 << np.arange(8 - 1, -1, -1))

    # Combine characters to original text
    return "".join(np.char.mod("%c", codeInIntCode))

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
    


    #if end_b != 0:
    #    payload = prefix + payload[end_b // 8:] 
    #else:
    #    payload = prefix + payload
    payload_bits, hide_sets = reshape_bits(payload)

    print("total", hide_sets, "sets need to be hidden")

    end_h = end_b // num_lsb 

    try:
        while True:
            mtext, mtype = rmq.receive(type=1)

            cbit_height = 56
            start_h = end_h
            if ((end_h + cbit_height) < hide_sets):
                end_h = end_h + cbit_height
            else:
                end_h = hide_sets
            ret, audioData = hide(mtext, payload_bits, start_h, end_h)
            print(decode(ret))
            if counter == 0:
                audioOut = audioData
            else:
                audioOut = np.append(audioOut, audioData)


            tmq.send(ret, block=False, type=1)
            end_h_hist[counter % 3] = end_h
            counter = counter + 1
            end_time = time.time()
            logging.debug("carrierlen %d start_h %d end_h %d %d bits %.2f firstb %x last %x" % 
                    (cbit_height, start_h, end_h, end_h * num_lsb,
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
    finally:
        wavfile.write("phaseout.wav", 8000, audioOut)
        if not hung_up:
            rmq.remove()
            tmq.remove()
            logging.info("queue removed")
    return end_h_hist[(counter - 2) % 3] 


def inject_loop(secret_filename):
    num_lsb = 3
    byte_depth = 1
    start_b = 0
    end_b = 0

    logging.basicConfig(level=logging.DEBUG)
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

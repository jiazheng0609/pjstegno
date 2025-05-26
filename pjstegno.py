import sysv_ipc
import time
import hashlib
import logging
from abc import ABC, abstractmethod

KEY = 81
TKEY = 82
prefix = bytearray(b'\x55\xaa')

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
        rmq = sysv_ipc.MessageQueue(KEY, flags=sysv_ipc.IPC_CREAT, mode=0o660)
        tmq = sysv_ipc.MessageQueue(TKEY, flags=sysv_ipc.IPC_CREAT, mode=0o660)

        logging.info(f"{rmq.id=}, {tmq.id=}")
        logging.info("waiting for a call to start...")
        start_time = time.time()
        counter = 0
        hung_up = 0
        
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
            logging.debug("phone hung up")
            hung_up = 1
            if end_h == hide_sets:
                return encoder.end_b(end_h)
            elif end_h > 0:
                return encoder.end_b(end_h_hist[(counter - 2)% 3])  - 16
        finally:
            if not hung_up:
                rmq.remove()
                tmq.remove()
                logging.debug("queue removed")
        return encoder.end_b(end_h)
    
    def extract_loop(self, decoder, filename, secret_len):
        end_h = 0
        decoded = b''
        secret_byte = bytearray(b'')

        while (end_h < secret_len):
            decoded, end_h = self.recv_and_extract(decoder, secret_len)
            secret_byte.extend(decoded)

        write_file(filename, secret_byte[:secret_len])
        print("wrote to file:", filename)
        md5val = hashlib.md5(secret_byte[:secret_len]).hexdigest()
        print(f"MD5: {md5val}")

    def recv_and_extract(self, decoder, secret_len):
        logging.info(f"{KEY=}")
        rmq = sysv_ipc.MessageQueue(KEY, flags=sysv_ipc.IPC_CREAT, mode=0o660)
        logging.info(f"{rmq.id=}")
        logging.info("waiting for a call to start...")
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
                        logging.debug("found preamble")
                        pos = dec_one.find(b'\x55\xaa')
                        dec_one = dec_one[pos+len(b'\x55\xaa'):]
                        found_start = 1
                    else:
                        logging.debug("waiting preamble...")
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
            logging.debug("phone hung up")
            hung_up = 1
        finally:
            if not hung_up:
                rmq.remove()
                logging.debug("queue removed")

        return decoded, end_h


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

class Decoder(ABC):
    @abstractmethod
    def extract(self):
        return

def write_file(filename, rcv_bytes):
    with open(filename, 'wb') as ofile:
        ofile.write(rcv_bytes)

def print_realtime_text(decode_one):
    try:
        text = str(decode_one, "utf-8")
        print(text, end='', flush=True)
    except UnicodeDecodeError:
        pass
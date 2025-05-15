import pjstegno
import lsb
import qim
import logging
import configparser

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    config = configparser.ConfigParser()
    config.read('pjstegno.cfg')

    if config['PJStegno']['encoding'] == 'LSB':
        num_lsb = int(config['LSB']['num_lsb'])
        byte_depth = int(config['LSB']['byte_depth'])
        decoder = lsb.LSBDecoder(num_lsb, byte_depth)
    elif config['PJStegno']['encoding'] == 'QIM':
        delta = float(config['QIM']['delta'])
        decoder = qim.QIMDecoder(delta)

    receiver = pjstegno.PJStegno()
    receiver.extract_loop(decoder, config['PJStegno']['output_file'],
                           int(config['PJStegno']['output_size']))
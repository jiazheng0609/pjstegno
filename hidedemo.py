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
        encoder = lsb.LSBEncoder(num_lsb, byte_depth)
    elif config['PJStegno']['encoding'] == 'QIM':
        delta = float(config['QIM']['delta'])
        encoder = qim.QIMEncoder(delta)

    receiver = pjstegno.PJStegno()
    receiver.inject_loop(encoder, config['PJStegno']['input_file'])
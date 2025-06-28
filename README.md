# PJSIP Steganography Python Script

This repo of files is intended to use along with PJSUA application inside [pjsip-stegno](https://github.com/jiazheng0609/pjsip-stegno) project.
  
The custom transport adapter in PJSIP will transfer payload inside RTP packets into a message queue, there's where the script get a carrier message to hide data in.


## Install dependency

```sh
pip install -r requirements.txt
``` 

## How to use

1. Change parameter in `pjstegno.cfg`, copy it to the working directory when executing the script.

2. For secret message sender, execute `hidedemo.py`.  
   For secret message receiver, execute `extractdemo.py`.  
   You need to start the script before a call started, let the message queue be created, otherwise PJSIP will not transfer payload into message queue.

3. Establish a call in PJSUA.  
  The sender side should be started after caller received a RTP message from callee.  
  The receiver should start storing decoded secret file after it founds the prefix in hiding space.  

4. After the secret file is completely transferred, calculated MD5 value appears on the screen.


## License

[MIT](LICENSE.md)

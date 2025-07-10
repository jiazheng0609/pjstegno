# PJSIP Steganography Python Script

This repository contains files intended to use along with the PJSUA application inside the [pjsip-stegno](https://github.com/jiazheng0609/pjsip-stegno) project.
  
The custom transport adapter in PJSIP will transfer payloads inside RTP packets into a message queue, which is where the script gets a carrier message to hide data in.


## Install dependencies

```sh
pip install -r requirements.txt
``` 

## How to use

1. Change parameters in `pjstegno.cfg`, copy it to the working directory where you will run the script.

2. For secret message sender, execute `hidedemo.py`.  
   For secret message receiver, execute `extractdemo.py`.  
   You need to start the script before a call started to let the message queue be created; otherwise, PJSIP will not transfer payloads into the message queue.

3. Establish a call in PJSUA.  
  The sender side should start hiding messages into payloads after caller has received the first RTP message from callee.  
  The receiver should start storing the decoded secret data after it finds the prefix in hiding space.  

4. Sender: After the secret file is completely transferred and the call has ended, the calculated MD5 value appears on the screen.  
  Receiver: After the secret file is completely transferred, the calculated MD5 value appears on the screen.


## License

[MIT](LICENSE.md)

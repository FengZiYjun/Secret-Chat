# Secret Chat
[![GitHub license](./img/apache2.svg)]()

*"This is a private conversation."*

Secret Chat allows you to chat with your important ones in an absolute private and secure manner.

Requirements
------
Python 3.6

Python packages:
tkinter, threading, socket, queue, time, select, pyaes


Setup
------
1. type in the command line `python server.py` to start the server process.

2. type in the command line `python client.py` to create a new client.

3. Enter your user name in the blanck and click "login".

4. Then you can chat with everyone connecting to the same server.

Usage
------
1. If you want to chat with someone online, click his/her name inside the name list and type words in the chat window.
2. To send words, you can either hit the "Enter" buttom of your keyboard or click the "send" buttom of the chat window. If you want to broadcast a message, click "ALL".
3. To exit the app, just click "Exit".

Notice
------
1. All data between server and client is powerfully encrypted under the TLS/SSL protocol used by HTTPS. Your personal infomation would never be known by the third.
2. *Secret Chat* is built for secret chatting. Therefore, neither the server nor the client stores your data, including your user name, account, friend list and chatting history. 

Technical Details
------
![](./img/HTTPS.png)


License
-------
© Ziyuan Feng, 2017. Licensed under an [Apache-2](./LICENSE) license.

# FoC Secure Messaging Using Openssl 
This is a secure Client-Server-Client message application.
- the server trusted by using CA's cert and authenticate the server's cert
- all message are signed and encrypted.
- the server can handle Multi clients using threads.
- The client will also have thread for receiving incoming messages and main thread to send messages.

## Compile 
To run this project:

- Open a terminal and run the server.cpp.
```sh
g++ -o server server.cpp -pthread -lcrypto
```
```sh
./server 1234
```
the [PORT] can be any avalible port
- Open other terminals and run the client.cpp. 
```sh
g++ -o client client.cpp -pthread -lcrypto 
```
```sh
./client localhost 1234 c1
```
the [PORT] should be the port of the server

## cmdcodes:
These codes that help to identify the messages structure and process it accordingly.
cmdcode |  Meaning 
---  |  ---
0 | the user exits the program
1 | the user requests the list of the online users
2 | the user requests to talk with another user
3 | the user receives an RTT and accept it.
4 | the user refuses the request
5 | message exchange between the two peers
6 | send ECDH_PUB_KEY and PUB_KEY to user who accepted the chat request
7 | bad request to unknown or unavalible user
8 | the peer exits the chat


## Authors
- **[Mohammed Mohammed](https://github.com/mohammedmrm)**
- **[Noushin Najafiragheb](https://github.com/nooshinnr)**

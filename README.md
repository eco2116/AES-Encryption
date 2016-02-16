# Network Security - Programming Assignment 1

Written by Evan O'Connor (eco2116)

### Compiling and running my program:

**Compiling**

```cd``` into directory containing files and run
```javac *.java```

**Running**

1. First, we spin up the server by running ```java server <port> <mode> <server privkey> <client pubkey>```
  * ```<port>``` is the port number on which the server will listen for a connection from the client
  * ```<mode>``` is a single lowercase letter, either t or u. t indicates trusted mode and u indicates untrusted 
  mode (file gets replaced)
  * ```<server privkey>``` is the location of the file storing the server's private RSA key. The user should provide the 
  file path relative to the directory where the executable is being run. This key must be generated using the ```generatekeys```
  main function and the file extension will be ```.key```
  * ```<client pubkey>``` is the location of the file storing the client's public RSA key. The same restrictions as 
   ```<server privkey>``` will apply.
  * Sample execution: ```java server 13267 t server_private.key client_public.key```

2. 




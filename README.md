# AES Encryption

Written by Evan O'Connor

### Compiling and running my program

**Compiling**

```cd``` into directory containing Java files and run
```javac *.java```

**Running**

1. If the user does not already have public and private RSA keys in the proper format stored in the same directory
   as the executables, they must generate keys by running ```java generatekeys <client or server>```
  * ```<client or server>``` accepts either the string "client" or "server" (without quotations). If client is chosen,
    then RSA public and private keys will separately be stored to the files ```client_public.key``` and ```client_private.key```. If server is chosen, ```server_public.key``` and ```server_private.key``` will be generated.
  * All of these four files must exist (in the same directory as the executables) in order to proceed to the server and    client.
  * Sample execution: ```java generatekeys client```

2. We spin up the server by running ```java server <port> <mode> <server privkey> <client pubkey>```
  * ```<port>``` is the port number on which the server will listen for a connection from the client
  * ```<mode>``` is a single lowercase letter, either t or u. t indicates trusted mode and u indicates untrusted 
  mode (file gets replaced). If using untrusted mode, ```fakefile``` must exist and the server will attempt to verify
  the signature using this file.
  * ```<server privkey>``` is the location of the file storing the server's private RSA key. The user should provide the 
  file path relative to the directory where the executable is being run. This key must be generated using the ```generatekeys```
  main function and the file extension will be ```.key```
  * ```<client pubkey>``` is the location of the file storing the client's public RSA key. The same restrictions as 
   ```<server privkey>``` will apply.
  * Sample execution: ```java server 13267 t server_private.key client_public.key```

3. Next, the client will connect to the server by running in another terminal window or on another machine, 
   ```java client <password> <filename> <server IP> <port> <server pubkey> <client privkey>```
  * ```<password>``` is the 16 character password used for AES encryption (only alphanumeric characters accepted)
  * ```<server IP>``` is the server's IP address or name
  * ```<port>``` is the port number to use when contacting the server.
  * ```<server pubkey>``` is the location of the file storing the server's public RSA key. The same restrictions as 
   ```<server privkey>``` from the server will apply.
  * ```<client privkey>``` is the location of the file storing the client's private RSA key. The same restrictions as 
   ```<server privkey>``` from the server will apply.
  * Sample execution: ```java client 0123456789ABCDEF test 127.0.0.1 13267 server_public.key client_private.key```

### Implementation Details

**crypto**

```crypto.java``` is a helper class containing static methods, custom exceptions, and a nested class to store AES keys. 

The one nested class I implemented is:
* ```Keys``` which stores two secret keys, one of which is used as the AES encryption key and the other which is used for
  authentication.

The helper functions I implemented are:
* ```generateKeysFromPassword``` uses a pseudorandom salt, a given number of iterations, the client's password to generate authentication and encryption keys to be used for AES encryption.
* ```encryptRSAPublic``` and ```encryptRSAPrivate``` handle RSA encryption using public and private keys, respectively. They do so by reading from the key files and utilizing a ```Cipher``` in encrypt mode.
* ```decryptRSAPublic``` and ```decryptRSAPrivate``` handle RSA decryption using public and private keys, respectively. They do so by reading from the key files and utilizing a ```Cipher``` in decrypt mode.
* ```readPublicKey``` and ```readPrivateKey``` handle reading public and private keys from the key files. The keys' modulus
and exponent are serialized and stored as ```BigInteger``` objects so any other key file format will fail. They use the appropriate key specs and key factories to generate Java ```PublicKey``` or ```PrivateKey``` objects from the deserialized data.
* ```generateHash``` uses a ```MessageDigest``` object to generate a hash of the data in a given file. While this method is
agnostic to the hashing algorithm used, this client server model I have created uses SHA-256.

The custom exceptions that I created are:
* ```InvalidPasswordException``` indicates that the password sent to the server was compromised, by using the authorization key
* ```RSAPrivateDecryptionException``` indicates failure during RSA decryption using a private key
* ```RSAPrivateEncryptionException``` indicates failure during RSA encryption using a private key
* ```RSAPublicDecryptionException``` indicates a failure during RSA decryption using a public key
* ```RSAPublicEncryptionException``` indicates a failure during RSA encryption using a public key
* ```HashingException``` indicates a failure while hashing data
* ```AESDecryptionException``` indicates a failure during AES decryption
* ```AESEncryptionException``` indicates a failure during AES encryption
* ```SocketException``` indicates a client is trying to connect to a closed socket

**generatekeys**

```generatekeys.java``` is a main function used to generate the public and private keys for either the server or client
that are necessary to run the server and the client, using the following functions:

* ```main``` takes in one argument, either client or server. If client is chosen, ```client_public.key``` and ```client_private.key``` are generated (likewise for server). The function is agnostic to the modulus size, but my
implementation uses a 2048-bit modulus.
* ```saveToFile``` handles the serialization and storing of the ```BigInteger``` objects that represent the key's
modulus and exponent. This will overwrite previously existing files with new key values.
* ```validationFailure``` handles validation of the input parameters.

**server and client**

```server.java``` and ```client.java``` are implemented directly following the assignment description (using Java's built-in security and crypto libraries).
* Maximum file size is 1MB.
* To generate an AES key from the client's password, I chose to use the ```PBKDF2WithHmacSHA1``` secret key spec.
* AES encryption is done in CBC mode using the ```PKCS5Padding``` cipher spec for padding.

**Resources**

I used the following online resources to guide me in understanding the assignment and developing this program.

* For socket file transfer
   * http://www.rgagnon.com/javadetails/java-0542.html
* For AES encryption/decryption
   * https://www.owasp.org/index.php/Using_the_Java_Cryptographic_Extensions#AES_Encryption_and_Decryption
* For RSA encryption/decryption
   * http://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
   * https://gist.github.com/dweymouth/11089238

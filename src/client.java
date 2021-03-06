import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;

import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;

/**
 * Evan O'Connor (eco2116)
 * Network Security - Programming Assignment 1
 *
 * client.java
 *
 * The client encrypts and signs a file, sending the server an encrypted key, the encrypted file, and the signature
 *
 */
public class client {

    private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";

    private static final int AES_KEY_LENGTH = 128;
    private static final int BUFF_SIZE = 1024;
    private static final int NUM_ARGS = 6;

    private static final long PAD_SIZE = 16;

    public static void validationFailure(String msg) {
        System.out.println(msg);
        System.out.println("Usage: java client <password> <filename> <server IP> <port> <server pubkey> <client privkey>");
        System.exit(0);
    }

    public static void main (String[] args) {

        // Validate input
        if(args.length != NUM_ARGS) { validationFailure("Incorrect number of arguments."); }
        String password = validatePassword(args[0]);
        String sendFile = validateFileName(args[1]);
        String address = validateIP(args[2]);
        int port = validatePort(args[3]);
        String pubKey = validateKey(args[4], true);
        String privKey = validateKey(args[5], false);

        // Connect to server on specified address and port
        Socket socket = null;
        try {
            socket = connectToServer(address, port);
        } catch(IOException e) {
            System.out.println("Failed to connect to server.");
            System.exit(0);
        }
        // Send encrypted password, file, and signature to server
        sendFile(socket, password, pubKey, privKey, sendFile);
    }

    private static Socket connectToServer(String addr, int port) throws IOException {
        Socket sock = null;
        try {
            System.out.println("Connecting to server...");
            // Make a connection to the server socket
            sock = new Socket(addr, port);
            System.out.println("Accepted connection : " + sock);
        } catch(IOException e) {
            System.out.println("Failed to create socket.");
        }
        return sock;
    }

    private static void sendFile(Socket socket, String password, String pubFile, String privFile, String sendFile) {
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        OutputStream os;
        try {
            // Send file to server
            File myFile = new File(sendFile);
            try {
                fis = new FileInputStream(myFile);
            } catch (FileNotFoundException e) {
                throw new FileNotFoundException("File not found with name: " + sendFile);
            }
            bis = new BufferedInputStream(fis);
            try {
                os = socket.getOutputStream();
            } catch(NullPointerException e) {
                throw new crypto.SocketException("Cannot connect to server. Make sure server is running and try again.");
            }

            // Send server AES secret encrypted using server's public key
            performRSAPublicEncryption(password, pubFile, os);
            os.flush();

            // Send server encrypted ciphertext
            performAESEncryption(password, fis, os, myFile);

            // Sleep so that server sees separation between file and signature
            Thread.sleep(1000);

            // Hash the plaintext file
            byte[] hashedPlaintext = performHashing(sendFile);

            // Encrypt and send hashed plaintext using client's private RSA key
            byte[] signature = performRSAPrivateEncryption(hashedPlaintext, privFile);
            os.write(signature);
            os.flush();

        // Send user-friendly error messages based on step being performed, close sockets/streams and exit nicely
        } catch (crypto.RSAPublicEncryptionException e) {
            System.out.println(e.getMessage());
        } catch (crypto.AESEncryptionException e) {
            System.out.println(e.getMessage());
        } catch (crypto.HashingException e) {
            System.out.println(e.getMessage());
        } catch (crypto.RSAPrivateEncryptionException e) {
            System.out.println(e.getMessage());
        } catch (FileNotFoundException e) {
            System.out.println(e.getMessage());
        } catch (crypto.SocketException e) {
            System.out.println(e.getMessage());
        } catch (InterruptedException e) {
            System.out.println("Client thread failed to sleep. Please try again.");
        } catch (IOException e) {
            System.out.println("Unexpected IO exception encountered.");
        } finally {
            closeStreamsAndSocket(fis, bis, socket);
        }
        System.out.println("Done.");
    }

    private static void performRSAPublicEncryption(String password, String pubFile, OutputStream os) throws crypto.RSAPublicEncryptionException {
        try { // Perform RSA encryption using public key on password
            os.write(crypto.encryptRSAPublic(password.getBytes(), pubFile));

        // Create user-friendly error messages
        } catch (NoSuchAlgorithmException e) {
            throw new crypto.RSAPublicEncryptionException("Could not find algorithm.");
        } catch (NoSuchPaddingException e) {
            throw new crypto.RSAPublicEncryptionException("Could not find padding.");
        } catch (InvalidKeyException e) {
            throw new crypto.RSAPublicEncryptionException("Invalid key.");
        } catch (IllegalBlockSizeException e) {
            throw new crypto.RSAPublicEncryptionException("Illegal block size.");
        } catch (BadPaddingException e) {
            throw new crypto.RSAPublicEncryptionException("Bad padding.");
        } catch (InvalidKeySpecException e) {
            throw new crypto.RSAPublicEncryptionException("Invalid key spec.");
        } catch (ClassNotFoundException e) {
            throw new crypto.RSAPublicEncryptionException("Class not found: BigInteger.");
        } catch (IOException e) {
            throw new crypto.RSAPublicEncryptionException("Unexpected IO exception.");
        }
    }

    private static byte[] performRSAPrivateEncryption(byte[] hashedPlaintext, String privFile) throws crypto.RSAPrivateEncryptionException {
        byte[] signature;
        try {
            // Perform RSA encrytpion using private key on hashed plaintext for signature
            signature = crypto.encryptRSAPrivate(hashedPlaintext, privFile);
        } catch (NoSuchAlgorithmException e) {
            throw new crypto.RSAPrivateEncryptionException("Could not find algorithm.");
        } catch (NoSuchPaddingException e) {
            throw new crypto.RSAPrivateEncryptionException("Could not find padding.");
        } catch (InvalidKeyException e) {
            throw new crypto.RSAPrivateEncryptionException("Invalid key.");
        } catch (IllegalBlockSizeException e) {
            throw new crypto.RSAPrivateEncryptionException("Illegal block size.");
        } catch (BadPaddingException e) {
            throw new crypto.RSAPrivateEncryptionException("Bad padding.");
        } catch (ClassNotFoundException e) {
            throw new crypto.RSAPrivateEncryptionException("Class not found: BigInteger");
        } catch (InvalidKeySpecException e) {
            throw new crypto.RSAPrivateEncryptionException("Invalid key spec");
        } catch (IOException e) {
            throw new crypto.RSAPrivateEncryptionException("Unexpected IO exception");
        }
        return signature;
    }

    private static void performAESEncryption(String password, FileInputStream fis, OutputStream os, File myFile) throws crypto.AESEncryptionException {
        try { // Perform AES encryption on file using password
            encryptFile(AES_KEY_LENGTH, password.toCharArray(), fis, os, myFile.length());
        // Create user-friendly error messages
        } catch (NoSuchPaddingException e) {
            throw new crypto.AESEncryptionException("Could not find padding.");
        } catch (NoSuchAlgorithmException e) {
            throw new crypto.AESEncryptionException("Could not find algorithm");
        } catch (InvalidKeyException e) {
            throw new crypto.AESEncryptionException("Invalid key");
        } catch (InvalidParameterSpecException e) {
            throw new crypto.AESEncryptionException("Invalid parameter spec");
        } catch (IllegalBlockSizeException e) {
            throw new crypto.AESEncryptionException("Illegal block size.");
        } catch (BadPaddingException e) {
            throw new crypto.AESEncryptionException("Bad padding");
        } catch (InvalidKeySpecException e) {
            throw new crypto.AESEncryptionException("Invalid key spec");
        } catch (IOException e) {
            throw new crypto.AESEncryptionException("Unexpected IO exception.");
        }
    }

    private static byte[] performHashing(String sendFile) throws crypto.HashingException {
        byte[] hashedPlaintext;
        try { // Perform hashing for signature
            hashedPlaintext = crypto.generateHash(crypto.HASHING_ALGORITHM, sendFile);
        // Generate user-friendly error messages
        } catch (NoSuchAlgorithmException e) {
            throw new crypto.HashingException("Could not find algorithm named: " + crypto.HASHING_ALGORITHM + ".");
        } catch (FileNotFoundException e) {
            throw new crypto.HashingException("Could not find file named: " + sendFile + ".");
        } catch (IOException e) {
            throw new crypto.HashingException("Unexpected IO exception encountered.");
        }
        return hashedPlaintext;
    }

    private static String validatePassword(String input) {
        if(input.length() != 16) {
            validationFailure("Password must be 16 characters long.");
        } else if(!input.matches("[A-Za-z0-9]+")) {
            validationFailure("Password must only contain alphanumeric characters.");
        }
        return input;
    }

    private static String validateFileName(String input) {
        File validate = new File(input);
        if(!validate.canRead()) {
            validationFailure("Cannot read from file: " + input);
        }
        return input;
    }

    private static String validateIP(String input) {
        try {
            // Check if host exists
            InetAddress.getByName(input);
        } catch (UnknownHostException e) {
            validationFailure("Could not find IP address/host name: " + input);
        }
        return input;
    }

    private static int validatePort(String input) {
        int port = 0;
        try {
            port = Integer.parseInt(input);
        } catch(NumberFormatException e) {
            validationFailure("Port must be an integer");
        }
        if(port > 65536) {
            validationFailure("Port value out of range. Must be <= 6535");
        }
        return port;
    }

    private static String validateKey(String input, boolean isPublic) {
        // Make sure file is readable
        validateFileName(input);

        // Keys generated from generatekeys.java must end with .key and be of the appropriate size
        if(!input.endsWith(crypto.RSA_KEY_EXTENSION)) {
            validationFailure("Keys must have .key extension");
        }
        File file = new File(input);
        if(isPublic && file.length() != crypto.PUBLIC_RSA_KEY_SIZE) {
            validationFailure("Invalid public RSA key size. Please generate new keys using generatekeys.");
        } else if(!isPublic && file.length() != crypto.PRIVATE_RSA_KEY_SIZE) {
            validationFailure("Invalid private RSA key size. Please generate new keys using generatekey.");
        }
        return input;
    }

    private static void closeStreamsAndSocket(FileInputStream fis, BufferedInputStream bis, Socket sock) {
        try {
            if (fis != null) fis.close();
            if (bis != null) bis.close();
            if (sock != null) sock.close();
        } catch(IOException e) {
            validationFailure("Failed to close streams and sockets.");
        }
    }

    private static void encryptFile(int keySize, char[] pass, InputStream inputStream, OutputStream outputStream, long fileSize)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException,
                    IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {

        // Send server the size in bytes of the encrypted file to be read
        byte[] bytes = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(fileSize + PAD_SIZE).array();
        outputStream.write(bytes);

        // Generate salt and keys (for authentication and encryption)
        byte[] salt = generateRandomSalt(crypto.SALT_SIZE);
        crypto.Keys secret = crypto.generateKeysFromPassword(keySize, pass, salt);

        Cipher encrCipher;

        // Initialize AES cipher
        encrCipher = Cipher.getInstance(CIPHER_SPEC);
        encrCipher.init(Cipher.ENCRYPT_MODE, secret.encr);

        // Generate initialization vector
        byte[] iv = encrCipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

        // Send authentication and AES initialization data
        outputStream.write(salt);
        outputStream.write(secret.auth.getEncoded());
        outputStream.write(iv);

        // Use a buffer to send chunks of encrypted data to server
        byte[] buff = new byte[BUFF_SIZE];
        int read;
        byte[] encr;

        while ((read = inputStream.read(buff)) > 0) {
            encr = encrCipher.update(buff, 0, read);
            if(encr != null) {
                outputStream.write(encr);
            }
        }
        // Final encryption block
        encr = encrCipher.doFinal();
        if(encr != null) {
            outputStream.write(encr);
        }
    }

    // Generate a random salt for secure password hashing
    private static byte[] generateRandomSalt(int size) {
        Random random = new SecureRandom();
        byte[] saltBytes = new byte[size];
        random.nextBytes(saltBytes);
        return saltBytes;
    }

}
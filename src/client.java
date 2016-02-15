import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;

public class client {

    private static final int AES_KEY_LENGTH = 128;
    private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";
    private static final int BUFF_SIZE = 1024;
    private static final long PAD_SIZE = 16;
    private static final int NUM_ARGS = 6;

    public static void validationFailure(String msg) {
        System.out.println(msg);
        System.out.println("Usage: java client <password> <filename> <server IP> <port> <server pubkey> <client privkey>");
        System.exit(0);
    }

    // TODO: throw exceptions up to main and close everything there!!
    // TODO: cite https://www.owasp.org/index.php/Using_the_Java_Cryptographic_Extensions#AES_Encryption_and_Decryption
    public static void main (String[] args) {

        // Validate input
        if(args.length != NUM_ARGS) {
            validationFailure("Incorrect number of arguments.");
        }

        String password = validatePassword(args[0]);
        String sendFile = validateFileName(args[1]);
        String address = validateIP(args[2]);
        int port = validatePort(args[3]);
        String pubKey = validateFileName(args[4]);
        String privKey = validateFileName(args[5]);

        // Connect to server on specified address and port
        Socket socket = null;
        try {
            socket = connectToServer(address, port);
        } catch(IOException e) {
            System.out.println("Failed to connect to server.");
            System.exit(0);
        }

        // Send encrypted password, file, and signature to server
        try {
            sendFile(socket, password, pubKey, privKey, sendFile);
        } catch(Exception e) {
            // TODO: handle exceptions separately
            failWithMessage("Failed to send file");
        }
    }

    private static Socket connectToServer(String addr, int port) throws IOException {
        Socket sock = null;
        try {
            System.out.println("Connecting...");
            // Make a connection to the server socket
            sock = new Socket(addr, port);
            System.out.println("Accepted connection : " + sock);
        } catch(IOException e) {
            failWithMessage("Failed to create socket.");
        }
        return sock;
    }

    // TODO: handle when client starts first
    private static void sendFile(Socket socket, String password, String pubFile, String privFile, String sendFile) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException, IOException, IllegalBlockSizeException, BadPaddingException, InterruptedException {

        FileInputStream fis = null;
        BufferedInputStream bis = null;
        OutputStream os;
        try {
            // Send file to server
            File myFile = new File(sendFile);
            fis = new FileInputStream(myFile);
            bis = new BufferedInputStream(fis);

            os = socket.getOutputStream();

            // Send server AES secret encrypted using server's public key
            os.write(crypto.encryptRSAPublic(password.getBytes(), pubFile));
            os.flush();

            // Send server encrypted ciphertext
            encryptFile(AES_KEY_LENGTH, password.toCharArray(), fis, os, myFile.length());

            // Sleep so that server sees separation between file and signature
            Thread.sleep(1000);

            // Hash the plaintext file
            byte[] hashedPlaintext = crypto.generateHash(crypto.HASHING_ALGORITHM, sendFile);

            // Encrypt and send hashed plaintext using client's private RSA key
            byte[] signature = crypto.encryptRSAPrivate(hashedPlaintext, privFile);
            System.out.println("sizeee : " + signature.length);
            os.write(signature);
            os.flush();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
            // TODO: fix this
            failWithMessage("File not found by name " + sendFile);
        } catch (IOException e) {
            e.printStackTrace();
            failWithMessage("Failed to send file to server.");
        } finally {
            closeStreamsAndSocket(fis, bis, socket);
        }
        System.out.println("Done.");
    }

    private static String validatePassword(String input) {
        if(input.length() != 16) {
            failWithMessage("Password must be 16 characters long.");
        } else if(!input.matches("[A-Za-z0-9]+")) {
            failWithMessage("Password must only contain alphanumeric characters.");
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

    // TODO: implement
    private static String validateIP(String input) {
        return input;
    }

    private static int validatePort(String input) {
        int port = 0;
        try {
            port = Integer.parseInt(input);
        } catch(NumberFormatException e) {
            failWithMessage("Port must be an integer");
        }
        if(port > 65536) {
            failWithMessage("Port value out of range. Must be <= 6535");
        }
        return port;
    }

    // TODO: print out usage
    private static void failWithMessage(String msg) {
        System.out.println("Client-side error encountered.");
        System.out.println(msg);
    }

    private static void closeStreamsAndSocket(FileInputStream fis, BufferedInputStream bis, Socket sock) {
        try {
            if (fis != null) fis.close();
            if (bis != null) bis.close();
            if (sock != null) sock.close();
        } catch(IOException e) {
            failWithMessage("Failed to close streams and sockets.");
        }
    }

    private static void encryptFile(int keySize, char[] pass, InputStream inputStream, OutputStream outputStream, long fileSize)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException,
                    IOException, IllegalBlockSizeException, BadPaddingException {

        // Send server the size in bytes of the encrypted file to be read
        byte[] bytes = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(fileSize + PAD_SIZE).array();
        outputStream.write(bytes);

        // Generate salt and keys (for authentication and encryption)
        byte[] salt = generateRandomSalt(crypto.SALT_SIZE);
        crypto.Keys secret = crypto.generateKeysFromPassword(keySize, pass, salt);

        Cipher encrCipher = null;

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
        int totalRead = 0;
        byte[] encr;

        while ((read = inputStream.read(buff)) > 0) {
            totalRead += read;
            encr = encrCipher.update(buff, 0, read);
            if(encr != null) {
                outputStream.write(encr);
            }
        }
        // Final encryption block
        encr = encrCipher.doFinal();
        if(encr != null) {
            totalRead += encr.length;
            outputStream.write(encr);
        }
        System.out.println("total read: " + totalRead);
    }

    // Generate a random salt for secure password hashing
    private static byte[] generateRandomSalt(int size) {
        Random random = new SecureRandom();
        byte[] saltBytes = new byte[size];
        random.nextBytes(saltBytes);
        return saltBytes;
    }

}
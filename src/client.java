import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;

import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;

public class client {

    public final static int SOCKET_PORT = 13267;      // you may change this
    public final static String SERVER = "127.0.0.1";  // localhost
    public final static String
            FILE_TO_SEND = "test.txt";

    private static final String AES_SPEC = "AES";
    private static final int AES_KEY_LENGTH = 128;

    // AES specification - changing will break existing encrypted streams!
    private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";

    // Key derivation specification - changing will break existing streams!
    private static final String KEY_GENERAITON_SPEC = "PBKDF2WithHmacSHA1";
    private static final int SALT_SIZE = 16; // in bytes
    private static final int AUTH_SIZE = 8; // in bytes
    private static final int AUTH_ITERATIONS = 32768;

    // Process input/output streams in chunks - arbitrary
    private static final int BUFF_SIZE = 1024;

    // TODO: throw exceptions up to main and close everything there!!
    // TODO: cite https://www.owasp.org/index.php/Using_the_Java_Cryptographic_Extensions#AES_Encryption_and_Decryption
    public static void main (String[] args) {

        /**
         * Password: The 16 character password may contain any alphanumeric character (i.e. lowercase,
         uppercase and digits). Note: special characters are not included in order to simplify the input.
         • filename: Clearly indicate in your README file if the path of the file provided as input must be the
         full path or relevant to the directory containing the executable. You may just require that the file be in
         the same directory as the executable.
         • server IP address or name
         • port number to use when contacting the server
         • Necessary RSA key components: any inputs (filenames) to provide the client the necessary
         information for the RSA keys . Key components should be read from files and not have to be typed
         by the user.
         */
        // TODO: use args
        String password = validatePassword("1234567890123456");
        //String filename = validateFileName(args[1]);
//        String address = validateIP(args[2]);
//        int port = validatePort(args[3]);

        // TODO: input properly
        String pubKey = "server_public.key";
        String privKey = "client_private.key";

        Socket socket = connectToServer();
        try {
            sendFile(socket, password, pubKey, privKey);
        } catch(Exception e) {
            // TODO: handle exceptions separately
            failWithMessage("Failed to send file");
        }

    }

    private static Socket connectToServer() {
        Socket sock = null;
        try {
            System.out.println("Connecting...");
            // Make a connection to the server socket
            sock = new Socket(SERVER, SOCKET_PORT);
            System.out.println("Accepted connection : " + sock);
        } catch(IOException e) {
            failWithMessage("Failed to create socket.");
        }
        return sock;
    }
    // TODO: handle when client starts first
    private static void sendFile(Socket socket, String password, String pubFile, String privFile) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException, IOException, IllegalBlockSizeException, BadPaddingException {

        FileInputStream fis = null;
        BufferedInputStream bis = null;
        OutputStream os;
        try {
            // Send file to server
            // TODO: remove this file to send thing
            File myFile = new File(FILE_TO_SEND);
            //byte[] mybytearray = new byte[(int) myFile.length()];
            fis = new FileInputStream(myFile);
            bis = new BufferedInputStream(fis);
            //bis.read(mybytearray, 0, mybytearray.length);


            os = socket.getOutputStream();

            // Send server AES secret encrypted using server's public key
            os.write(crypto.encryptRSAPublic(password.getBytes(), pubFile));

            // Send server encrypted ciphertext
            //encryptFile(AES_KEY_LENGTH, password.toCharArray(), fis, os);

            // Hash the plaintext file
            byte[] hashedPlaintext = crypto.generateHash(crypto.HASHING_ALGORITHM, FILE_TO_SEND);

            // Encrypt and send hashed plaintext using client's private RSA key
            //os.write(crypto.encryptRSAPrivate(hashedPlaintext, privFile));

            //System.out.println("Sending " + FILE_TO_SEND + "(" + mybytearray.length + " bytes)");
            //os.write(mybytearray, 0, mybytearray.length);
            //os.flush();
        } catch (FileNotFoundException e) {
            failWithMessage("File not found by name " + FILE_TO_SEND);
        } catch (IOException e) {
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

    // TODO: validate file name
    private static String validateFileName(String input) {
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

    private static void encryptFile(int keySize, char[] pass, InputStream inputStream, OutputStream outputStream)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException,
                    IOException, IllegalBlockSizeException, BadPaddingException {

//        // Check for valid key length
//        if(keySize != AES_KEY_LENGTH) {
//            failWithMessage("Invalid AES key size.");
//            // TODO: throw an exception
//            System.exit(0);
//        }

        // Generate salt and keys (for authentication and encryption)
        byte[] salt = generateRandomSalt(SALT_SIZE);
        crypto.Keys secret = crypto.generateKeysFromPassword(keySize, pass, salt);

        Cipher encrCipher = null;

        // Initialize AES cipher
        encrCipher = Cipher.getInstance(CIPHER_SPEC);
        encrCipher.init(Cipher.ENCRYPT_MODE, secret.encr);

        // Generate initialization vector
        byte[] iv = encrCipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

        // Send authentication and AES initialization data
        // outputStream.write(keySize / 8);
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
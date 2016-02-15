import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.util.Arrays;

public class server {

    private final static String STORE_FILE = "decryptedfile";
    private final static String FAKE_FILE = "fakefile";
    private static final int AES_KEY_LENGTH = 128;
    private static final int ENCR_PASS_SIZE = 256;

    public static void validationFailure(String msg) {
        System.out.println(msg);
        System.out.println("Usage: java server <port> <mode> <server privkey> <client pubkey>");
        System.exit(0);
    }

    // TODO: cite http://www.rgagnon.com/javadetails/java-0542.html
    public static void main(String[] args) {
        // Input and validate client parameters
        if(args.length != 4) { validationFailure("Incorrect number of arguments."); }
        int port = validatePort(args[0]);
        String trustedMode = validateTrustMode(args[1]);
        String privKey = validateFileName(args[2]);
        String pubKey = validateFileName(args[3]);

        // Wait for client to accept connection on socket
        Socket socket = acceptSocket(port);
        if (socket != null) {
            // Read in encrypted data from client and perform encryption
            receiveFile(socket, privKey, pubKey, trustedMode.equals("t"));
        } else {
            System.out.println("Exiting...");
        }
    }

    private static Socket acceptSocket(int port) {
        ServerSocket servSock = null;
        try { // Begin accepting connections
            System.out.println("Waiting for client to connect...");
            servSock = new ServerSocket(port);
            return servSock.accept();
        } catch (UnknownHostException e) {
            System.out.println("Failed to create socket due to unknown host.");
        } catch (IOException e) {
            System.out.println("Failed to create socket.");
        } finally {
            try {
                if(servSock != null) servSock.close();
            } catch(IOException e) {
                System.out.println("Failed to close server socket.");
                System.exit(0);
            }
        }
        return null;
    }

    private static void receiveFile(Socket socket, String privKey, String pubKey, boolean isTrusted) {
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        try {
            int bytesRead; // Receive and decrypt password from client
            InputStream is;
            byte[] myByteArray = new byte[ENCR_PASS_SIZE];
            is = socket.getInputStream();

            try { // Attempt to output stream for decrypted file
                fos = new FileOutputStream(STORE_FILE);
            } catch(FileNotFoundException e) {
                throw new FileNotFoundException("File not found by name: " + STORE_FILE);
            }
            bos = new BufferedOutputStream(fos);
            bytesRead = is.read(myByteArray, 0, myByteArray.length);

            // Decrypt the AES password using server's private key
            byte[] decryptedPass = performRSAPrivateDecryption(myByteArray, privKey);

            // Convert byte stream to char stream for password (we know this is valid due to client-side password constraints)
            char[] password = (new String(decryptedPass)).toCharArray();

            // AES decryption in CBC mode
            performAESDecryption(password, is, bos);
            System.out.println("Generated " + STORE_FILE + " (" + bytesRead + " bytes read)");

            // Validate signature
            byte[] buffer = new byte[256];
            byte[] decrypted = null;
            while ((is.read(buffer)) > 0) {
                decrypted = performRSAPublicDecryption(buffer, pubKey);
            }

            // Compare hashed plaintext to decrypted signature
            String verifyFile = isTrusted ? STORE_FILE : FAKE_FILE;
            byte[] hash = performHashing(verifyFile);
            if(Arrays.equals(decrypted, hash)) {
                System.out.println("Verification Passed");
            } else {
                System.out.println("Verification Failed");
            }
            System.out.println("Done");

        // Send user-friendly error messages based on step being performed, close sockets/streams and exit nicely
        } catch (crypto.RSAPrivateDecryptionException e) {
            System.out.println(e.getMessage());
        } catch (crypto.AESDecryptionException e) {
            System.out.println(e.getMessage());
        } catch (crypto.RSAPublicDecryptionException e) {
            System.out.println(e.getMessage());
        } catch (crypto.HashingException e) {
            System.out.println(e.getMessage());
        } catch (FileNotFoundException e) {
            System.out.println(e.getMessage());
        } catch (IOException e) {
            System.out.println("Unexpected IO exception encountered.");
        } finally {
            closeStreamsAndSocket(fos, bos, socket);
        }
    }

    private static void decryptFile(char[] password, InputStream inputStream, OutputStream outputStream) throws IOException,
            crypto.InvalidPasswordException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {

        // Read in ciphertext file size
        byte[] sizeBytes = new byte[Long.SIZE / Byte.SIZE];
        inputStream.read(sizeBytes);
        long decryptSize = convertByteArrayToLong(sizeBytes);

        // Read in salt, keys, and authentication password
        byte[] saltBytes = new byte[crypto.SALT_SIZE];
        inputStream.read(saltBytes);
        crypto.Keys keys = crypto.generateKeysFromPassword(AES_KEY_LENGTH, password, saltBytes);
        byte[] auth = new byte[crypto.AUTH_SIZE];
        inputStream.read(auth);
        if(!Arrays.equals(keys.auth.getEncoded(), auth)) {
            throw new crypto.InvalidPasswordException();
        }

        // Initialize AES decryption cipher
        byte[] iv = new byte[crypto.IV_SIZE];
        inputStream.read(iv);
        Cipher decrpytCipher = Cipher.getInstance(crypto.CIPHER_SPEC);
        decrpytCipher.init(Cipher.DECRYPT_MODE, keys.encr, new IvParameterSpec(iv));

        // Use a buffer to decrypt and write to disk
        byte[] buff = new byte[crypto.BUFF_SIZE];
        int read;
        byte[] decrypt;

        // Read in and decrypt specified number of bytes (based on size specifications, we know this cast will not fail)
        read = inputStream.read(buff, 0, (int) decryptSize);
        decrypt = decrpytCipher.update(buff, 0, read);
        if(decrypt != null) {
            outputStream.write(decrypt);
        }
        outputStream.flush();

        // Decrypt final block
        decrypt = decrpytCipher.doFinal();
        if(decrypt != null) {
            outputStream.write(decrypt);
        }
        outputStream.flush();
    }

    private static byte[] performRSAPublicDecryption(byte[] buffer, String pubKey) throws crypto.RSAPublicDecryptionException {
        byte[] decrypted;
        try {
            decrypted = crypto.decryptRSAPublic(buffer, pubKey);
        } catch (IOException e) {
            throw new crypto.RSAPublicDecryptionException("Unexpected IO exception.");
        } catch (NoSuchAlgorithmException e) {
            throw new crypto.RSAPublicDecryptionException("Could not find algorithm.");
        } catch (NoSuchPaddingException e) {
            throw new crypto.RSAPublicDecryptionException("Could not find padding.");
        } catch (InvalidKeyException e) {
            throw new crypto.RSAPublicDecryptionException("Invalid key.");
        } catch (IllegalBlockSizeException e) {
            throw new crypto.RSAPublicDecryptionException("Illegal block size.");
        } catch (BadPaddingException e) {
            throw new crypto.RSAPublicDecryptionException("Bad padding.");
        }
        return decrypted;
    }

    private static byte[] performRSAPrivateDecryption(byte[] myByteArray, String privKey) throws crypto.RSAPrivateDecryptionException {
        // Use crypto helper function to decrypt using RSA private key; provide user-friendly errors
        byte[] decryptedPass;
        try {
            decryptedPass = crypto.decryptRSAPrivate(myByteArray, privKey);
        // Provide user-friendly error handling
        } catch (IOException e) {
            throw new crypto.RSAPrivateDecryptionException("Unexpected IO exception.");
        } catch (NoSuchAlgorithmException e) {
            throw new crypto.RSAPrivateDecryptionException("Could not find algorithm.");
        } catch (NoSuchPaddingException e) {
            throw new crypto.RSAPrivateDecryptionException("Could not find padding.");
        } catch (InvalidKeyException e) {
            throw new crypto.RSAPrivateDecryptionException("Invalid key.");
        } catch (IllegalBlockSizeException e) {
            throw new crypto.RSAPrivateDecryptionException("Illegal block size");
        } catch (BadPaddingException e) {
            throw new crypto.RSAPrivateDecryptionException("Bad padding.");
        }
        return decryptedPass;
    }

    private static void performAESDecryption(char[] password, InputStream is, BufferedOutputStream bos)
            throws crypto.AESDecryptionException {
        try {
            // Use crypto AES decryption helper function
            decryptFile(password, is, bos);
        // Provide user-friendly error handling
        } catch (IOException e) {
            throw new crypto.AESDecryptionException("Unexpected IO Exception.");
        } catch (crypto.InvalidPasswordException e) {
            throw new crypto.AESDecryptionException("Invalid password.");
        } catch (NoSuchPaddingException e) {
            throw new crypto.AESDecryptionException("Could not find padding.");
        } catch (NoSuchAlgorithmException e) {
            throw new crypto.AESDecryptionException("Could not find algorithm.");
        } catch (InvalidKeyException e) {
            throw new crypto.AESDecryptionException("Invalid key.");
        } catch (InvalidAlgorithmParameterException e) {
            throw new crypto.AESDecryptionException("Invalid algorithm parameter.");
        } catch (IllegalBlockSizeException e) {
            throw new crypto.AESDecryptionException("Illegal block size.");
        } catch (BadPaddingException e) {
            throw new crypto.AESDecryptionException("Bad padding");
        } catch (ShortBufferException e) {
            throw new crypto.AESDecryptionException("Short buffer");
        }
    }

    private static byte[] performHashing(String verifyFile) throws crypto.HashingException {
        byte[] hash;
        try {
            hash = crypto.generateHash(crypto.HASHING_ALGORITHM, verifyFile);
        } catch (NoSuchAlgorithmException e) {
            throw new crypto.HashingException("Could not find algorithm named " + crypto.HASHING_ALGORITHM + ".");
        } catch (FileNotFoundException e) {
            throw new crypto.HashingException("Could not find file named " + verifyFile + ".");
        } catch (IOException e) {
            throw new crypto.HashingException("Unexpected IO exception");
        }
        return hash;
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

    private static String validateTrustMode(String input) {
        if(!input.equals("t") && !input.equals("u")) {
            validationFailure("Trusted mode must be set to t or u");
        } else if(input.equals("u")) {
            // Verify fakefile exists
            validateFileName(FAKE_FILE);
        }
        return input;
    }

    private static void closeStreamsAndSocket(FileOutputStream fos, BufferedOutputStream bos, Socket sock) {
        try {
            if (fos != null) fos.close();
            if (bos != null) bos.close();
            if (sock != null) sock.close();
        } catch(IOException e) {
            System.out.println("Failed to close streams and sockets.");
        }
    }

    private static long convertByteArrayToLong(byte[] bytes) {
        long value = 0;
        // Use fact that first byte is most significant
        for (int i = 0; i < bytes.length; i++) {
            value = (value << 8) + (bytes[i] & 0xff);
        }
        return value;
    }

    private static String validateFileName(String input) {
        File validate = new File(input);
        if(!validate.canRead()) {
            validationFailure("Cannot read from file: " + input);
        }
        return input;
    }
}
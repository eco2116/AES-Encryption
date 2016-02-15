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
        if(args.length != 4) {
            validationFailure("Incorrect number of arguments.");
        }

        // Input and validate client parameters
        int port = validatePort(args[0]);
        String trustedMode = validateTrustMode(args[1]);
        String privKey = validateFileName(args[2]);
        String pubKey = validateFileName(args[3]);

        Socket socket = acceptSocket(port);

        try {
            receiveFile(socket, privKey, pubKey, trustedMode.equals("t"));
        } catch(Exception e) {
            // TODO: handle each exception
            System.out.println("exception in receive file");
            e.printStackTrace();
        }
    }

    // TODO: figure out exiting... close sockets before fail with message?
    private static Socket acceptSocket(int port) {
        ServerSocket servSock = null;

        // Begin accepting connections
        try {
            System.out.println("Waiting...");
            servSock = new ServerSocket(port);
            return servSock.accept();
        } catch (UnknownHostException e) {
            failWithMessage("Failed to create socket due to unknown host.");
        } catch (IOException e) {
            failWithMessage("Failed to create socket.");
        } finally {
            try {
                if(servSock != null) servSock.close();
            } catch(IOException e) {
                failWithMessage("Failed to close server socket.");
                System.exit(0);
            }
        }
        return null;
    }

    private static void receiveFile(Socket socket, String privKey, String pubKey, boolean isTrusted) throws Exception {
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        try {
            int bytesRead; // Receive and decrypt password from client
            InputStream is;
            byte[] myByteArray = new byte[ENCR_PASS_SIZE];
            is = socket.getInputStream();
            fos = new FileOutputStream(STORE_FILE);
            bos = new BufferedOutputStream(fos);
            bytesRead = is.read(myByteArray, 0, myByteArray.length);

            // Decrypt the AES password using server's private key
            byte[] decryptedPass = crypto.decryptRSAPrivate(myByteArray, privKey);

            // Convert byte stream to char stream for password (we know this is valid due to client-side password constraints)
            char[] password = (new String(decryptedPass)).toCharArray();
            decryptFile(password, is, bos);

            System.out.println("File " + STORE_FILE + " downloaded (" + bytesRead + " bytes read)");

            // Validate signature
            byte[] buffer = new byte[256];
            byte[] decrypted = null;

            while ((is.read(buffer)) > 0) {
                decrypted = crypto.decryptRSAPublic(buffer, pubKey);
            }

            // Compare hashed plaintext to decrypted signature
            String verifyFile = isTrusted ? STORE_FILE : FAKE_FILE;
            byte[] hash = crypto.generateHash(crypto.HASHING_ALGORITHM, verifyFile);
            if(Arrays.equals(decrypted, hash)) {
                System.out.println("Verification Passed");
            } else {
                System.out.println("Verification Failed");
            }

            System.out.println("done");

        } catch (FileNotFoundException e) {
            failWithMessage("File could not be found.");
        } catch (IOException e) {
            failWithMessage("Failed to receive file due to unexpected exception.");
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
        System.out.println("val" + decryptSize);

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

        // TODO: handle cast
        // Read in and decrypt specified number of bytes
        read = inputStream.read(buff, 0, (int) decryptSize);
        decrypt = decrpytCipher.update(buff, 0, read);
        if(decrypt != null) {
            outputStream.write(decrypt);
        }
        outputStream.flush();

        // Decrypt final block
        System.out.println("read" + read);
        decrypt = decrpytCipher.doFinal();
        if(decrypt != null) {
            outputStream.write(decrypt);
        }
        outputStream.flush();
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

    private static String validateTrustMode(String input) {
        if(!input.equals("t") && !input.equals("u")) {
            failWithMessage("Trusted mode must be set to t or u");
        }
        return input;
    }
    // TODO: print out usage
    private static void failWithMessage(String msg) {
        System.out.println("Server-side error encountered.");
        System.out.println(msg);
    }

    // TODO: Validate RSA file names

    private static void closeStreamsAndSocket(FileOutputStream fos, BufferedOutputStream bos, Socket sock) {
        try {
            if (fos != null) fos.close();
            if (bos != null) bos.close();
            if (sock != null) sock.close();
        } catch(IOException e) {
            failWithMessage("Failed to close streams and sockets.");
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

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.util.Arrays;

public class server {

    public final static int SOCKET_PORT = 13267;  // you may change this
    public final static String FILE_TO_RECEIVED = "decryptedfile";  // you may change this
    public final static int FILE_SIZE = 6022386;
    private static final String AES_SPEC = "AES";
    private static final int AES_KEY_LENGTH = 128;

    // TODO: understand why
    private static final int ENCR_PASS_SIZE = 256;

    // TODO: Move to crypto
    // AES specification - changing will break existing encrypted streams!
    private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";

    // Key derivation specification - changing will break existing streams!
    private static final String KEY_GENERAITON_SPEC = "PBKDF2WithHmacSHA1";
    private static final int SALT_SIZE = 16; // in bytes
    private static final int AUTH_SIZE = 8; // in bytes
    private static final int AUTH_ITERATIONS = 32768;

    // Process input/output streams in chunks - arbitrary
    private static final int BUFF_SIZE = 1024;

    // TODO: is this really what it is?

    // TODO: cite http://www.rgagnon.com/javadetails/java-0542.html
    public static void main(String[] args) {
        /**
         *  The port number on which the server will listen for a connection from the client.
         • mode: A single lowercase character of t or u. t means trusted mode, u means untrusted mode (file
         gets replaced).
         • Necessary RSA key components: any inputs (filenames) to provide the server the necessary
         information for the RSA keys . Key components should be read from files and not have to be typed
         by the user.
         Notes on the details
         */
        // Input and validate client parameters
//        int port = validatePort(args[0]);
//        String trustedMode = validateTrustMode(args[1]);

        String privKey = "server_private.key";
        String pubKey = "client_public.key";

        Socket socket = acceptSocket();

        try {
            receiveFile(socket, privKey, pubKey);
        } catch(Exception e) {
            // TODO: handle each exception
            System.out.println("exception in receive file");
            e.printStackTrace();
        }



    }

    // TODO: figure out exiting... close sockets before fail with message?
    private static Socket acceptSocket() {
        ServerSocket servSock = null;
        // Begin accepting connections
        try {
            System.out.println("Waiting...");
            servSock = new ServerSocket(SOCKET_PORT);
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

    private static void receiveFile(Socket socket, String privKey, String pubKey) throws Exception {
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        // Receive and decrypt password from client
        try {
            int bytesRead;
            InputStream is;
            byte[] myByteArray = new byte[ENCR_PASS_SIZE];
            is = socket.getInputStream();
            fos = new FileOutputStream(FILE_TO_RECEIVED);
            bos = new BufferedOutputStream(fos);
            bytesRead = is.read(myByteArray, 0, myByteArray.length);

            // Decrypt the AES password using server's private key
            byte[] decryptedPass = crypto.decryptRSAPrivate(myByteArray, privKey);
            //bos.write(decryptedPass, 0, decryptedPass.length);
            //bos.flush();

            // Convert byte stream to char stream for password (we know this is valid due to client-side password constraints)
            char[] password = (new String(decryptedPass)).toCharArray();
            decryptFile(password, is, bos);

            System.out.println("File " + FILE_TO_RECEIVED
                    + " downloaded (" + bytesRead + " bytes read)");

            // Validate signature

            int current = 0;
//            do {
//                bytesRead = is.read(myByteArray, current, (myByteArray.length - current));
//                if (bytesRead >= 0) current += bytesRead;
//            } while (bytesRead > -1);

            byte[] buffer = new byte[256];
            int numRead;

            byte[] decrypted = null;
            while ((numRead = is.read(buffer)) > 0) {
                decrypted = crypto.decryptRSAPublic(buffer, pubKey);
                //fos.write(decrypted);
                //fos.flush();
            }

            byte[] hash = crypto.generateHash(crypto.HASHING_ALGORITHM, "decryptedfile");
            

            System.out.println("done" + decrypted.length);

        } catch (FileNotFoundException e) {
            failWithMessage("File could not be found.");
        } catch (IOException e) {
            failWithMessage("Failed to receive file due to unexpected exception.");
        } finally {
            closeStreamsAndSocket(fos, bos, socket);
        }
    }

    private static int decryptFile(char[] password, InputStream inputStream, OutputStream outputStream) throws IOException,
            crypto.InvalidPasswordException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {

        // Read in ciphertext file size
        byte[] sizeBytes = new byte[Long.SIZE / Byte.SIZE];
        inputStream.read(sizeBytes);

        long decryptSize = convertByteArrayToLong(sizeBytes);
        System.out.println("val" + decryptSize);

        // Read in salt, keys, and authentication password
        byte[] saltBytes = new byte[SALT_SIZE];
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

//        do((read = inputStream.read(buff, 0, (int) decryptSize)) > 0) {
//            decrypt = decrpytCipher.update(buff, 0, read);
//            if(decrypt != null) {
//                outputStream.write(decrypt);
//            }
//        }
        // TODO: handle cast
        // Read in and decrypt specified number of bytes
        read = inputStream.read(buff, 0, (int) decryptSize);
        decrypt = decrpytCipher.update(buff, 0, read);
        if(decrypt != null) {
            outputStream.write(decrypt);
        }
        outputStream.flush();

        //System.out.println("diff" + decrpytCipher.getBlockSize());

        // Decrypt final block
        System.out.println("read" + read);
        decrypt = decrpytCipher.doFinal();
        if(decrypt != null) {
            outputStream.write(decrypt);
        }
        outputStream.flush();

        // TODO: return void?
        return crypto.AES_KEY_LENGTH;
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
}
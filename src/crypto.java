import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class crypto {

    public final static int SOCKET_PORT = 13267;  // you may change this
    public final static String FILE_TO_RECEIVED = "test_new.txt";  // you may change this
    public final static int FILE_SIZE = 6022386;
    public static final String AES_SPEC = "AES";
    public static final int AES_KEY_LENGTH = 128;
    public static final int IV_SIZE = 16;

    // TODO: Move to crypto
    // AES specification - changing will break existing encrypted streams!
    public static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";

    // Key derivation specification - changing will break existing streams!
    public static final String KEY_GENERAITON_SPEC = "PBKDF2WithHmacSHA1";
    public static final int SALT_SIZE = 16; // in bytes
    public static final int AUTH_SIZE = 8; // in bytes
    public static final int AUTH_ITERATIONS = 32768;

    // Process input/output streams in chunks - arbitrary
    public static final int BUFF_SIZE = 1024;

    // TODO: possibly move this stuff to a shareable static class
    // Class to store pair of encryption and authentication keys
    public static class Keys {
        public final SecretKey encr, auth;
        public Keys(SecretKey encr, SecretKey auth) {
            this.encr = encr;
            this.auth = auth;
        }
    }

    public static crypto.Keys generateKeysFromPassword(int size, char[] pass, byte[] salt) {
        SecretKeyFactory secretKeyFactory = null;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance(KEY_GENERAITON_SPEC);
        } catch(NoSuchAlgorithmException e) {
            failWithMessage("Failed to generate secret key factor.");
        }
        KeySpec keySpec = new PBEKeySpec(pass, salt, AUTH_ITERATIONS, size + AUTH_SIZE * 8);
        SecretKey tmpKey = null;
        try {
            tmpKey = secretKeyFactory.generateSecret(keySpec);
        } catch(InvalidKeySpecException e) {
            failWithMessage("Failed to generate secret due to invalid key spec.");
        }
        byte[] key = tmpKey.getEncoded();
        SecretKey auth = new SecretKeySpec(Arrays.copyOfRange(key, 0, AUTH_SIZE), AES_SPEC);
        SecretKey enc = new SecretKeySpec(Arrays.copyOfRange(key, AUTH_SIZE, key.length), AES_SPEC);
        return new crypto.Keys(enc, auth);
    }

    public static void failWithMessage(String msg) {
        System.out.println("Server-side error encountered.");
        System.out.println(msg);
    }

    public static class InvalidPasswordException extends Exception { }

    /**
     * Thrown if an attempt is made to encrypt a stream with an invalid AES key length.
     */
    public static class InvalidKeyLengthException extends Exception {
        InvalidKeyLengthException(int length) {
            super("Invalid AES key length: " + length);
        }
    }

    /**
     * Thrown if 192- or 256-bit AES encryption or decryption is attempted,
     * but not available on the particular Java platform.
     */
    public static class StrongEncryptionNotAvailableException extends Exception {
        public StrongEncryptionNotAvailableException(int keySize) {
            super(keySize + "-bit AES encryption is not available on this Java platform.");
        }
    }

    /**
     * Thrown if an attempt is made to decrypt an invalid AES stream.
     */
    public static class InvalidAESStreamException extends Exception {
        public InvalidAESStreamException() { super(); };
        public InvalidAESStreamException(Exception e) { super(e); }
    }

}

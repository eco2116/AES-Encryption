import sun.nio.cs.StandardCharsets;
import sun.security.util.BigInt;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
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

    public static final String HASHING_ALGORITHM = "SHA-256";
    public static final String RSA_ALGORITHM = "RSA";

    // TODO: possibly move this stuff to a shareable static class
    // Class to store pair of encryption and authentication keys
    public static class Keys {
        public final SecretKey encr, auth;
        public Keys(SecretKey encr, SecretKey auth) {
            this.encr = encr;
            this.auth = auth;
        }
    }
    // TODO: some of these can probably be moved out
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

    public static byte[] encryptRSAPublic(byte[] data, String fileName) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // Read public key from specified file
        PublicKey publicKey = readPublicKey(fileName);

        // Generate an RSA cipher to encrypt data
        Cipher encryptionCipher = Cipher.getInstance("RSA");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptionCipher.doFinal(data);
    }

    public static byte[] encryptRSAPrivate(byte[] data, String fileName) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // Read private key from specified file
        PrivateKey privateKey = readPrivateKey(fileName);

        // Generate an RSA cipher to encrypt data
        Cipher encryptionCipher = Cipher.getInstance("RSA");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return encryptionCipher.doFinal(data);
    }

    public static byte[] decryptRSAPrivate(byte[] data, String fileName) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // Read private key from specified file
        PrivateKey privateKey = readPrivateKey(fileName);

        // Generate an RSA cipher to decrypt data
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSAPublic(byte[] data, String fileName) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // Read public key from specified file
        PublicKey publicKey = readPublicKey(fileName);

        // Generate an RSA cipher to decrypt data
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static PublicKey readPublicKey(String fileName) throws IOException {
        File file = new File(fileName);
        FileInputStream fis = new FileInputStream(file);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(fis));

        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            return fact.generatePublic(keySpec);

        } catch(Exception e) {
            // TODO: fix exceptions
            failWithMessage("Failed to read public key.");
        } finally {
            fis.close();
            oin.close();
        }
        return null;
    }

    // TODO: maybe combine private / public methods
    private static PrivateKey readPrivateKey(String fileName) throws IOException {
        File file = new File(fileName);
        FileInputStream fis = new FileInputStream(file);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(fis));

        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            return fact.generatePrivate(keySpec);

        } catch(Exception e) {
            // TODO: fix exceptions
            failWithMessage("Failed to read private key.");
        } finally {
            fis.close();
            oin.close();
        }
        return null;
    }

    public static byte[] generateHash(String type, String file) throws NoSuchAlgorithmException, FileNotFoundException,
            IOException {

        // Initialize message digest for given hashing algorithm and file input stream
        MessageDigest messageDigest = MessageDigest.getInstance(type);
        FileInputStream fis = new FileInputStream(file);

        // Read plaintext in chunks and update the message digest
        byte[] buffer = new byte[BUFF_SIZE];
        int read;
        while((read = fis.read(buffer)) != -1) {
            messageDigest.update(buffer, 0, read);
        }
        // Finished using file input stream
        fis.close();

        // Digest hashed bytes
        return messageDigest.digest();
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

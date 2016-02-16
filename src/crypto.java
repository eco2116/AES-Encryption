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

/**
 * Evan O'Connor (eco2116)
 * Network Security - Programming Assignment 1
 *
 * crypto.java
 *
 * Helper class for cryptographic functions to be used by server, client
 *
 */
public class crypto {

    public static final String AES_SPEC = "AES";
    public static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";
    public static final String KEY_GENERATION_SPEC = "PBKDF2WithHmacSHA1";
    public static final String HASHING_ALGORITHM = "SHA-256";
    public static final String RSA_ALGORITHM = "RSA";
    public static final String RSA_KEY_EXTENSION = ".key";

    public static final int IV_SIZE = 16;
    public static final int SALT_SIZE = 16;
    public static final int AUTH_SIZE = 8;
    public static final int AUTH_ITERATIONS = 32768;
    public static final int BUFF_SIZE = 1024 * 1024;
    public static final int PRIVATE_RSA_KEY_SIZE = 751;
    public static final int PUBLIC_RSA_KEY_SIZE = 498;

    // Class to store pair of encryption and authentication keys
    public static class Keys {
        public final SecretKey encr, auth;
        public Keys(SecretKey encr, SecretKey auth) {
            this.encr = encr;
            this.auth = auth;
        }
    }

    public static crypto.Keys generateKeysFromPassword(int size, char[] pass, byte[] salt) throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        // Initialize and generate secret keys from password and pseudorandom salt
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KEY_GENERATION_SPEC);
        KeySpec keySpec = new PBEKeySpec(pass, salt, AUTH_ITERATIONS, size + AUTH_SIZE * 8);
        SecretKey tmpKey = secretKeyFactory.generateSecret(keySpec);
        byte[] key = tmpKey.getEncoded();

        // Save encryption and authorization keys in crypto.Keys static storage class
        SecretKey auth = new SecretKeySpec(Arrays.copyOfRange(key, 0, AUTH_SIZE), AES_SPEC);
        SecretKey enc = new SecretKeySpec(Arrays.copyOfRange(key, AUTH_SIZE, key.length), AES_SPEC);
        return new crypto.Keys(enc, auth);
    }

    public static byte[] encryptRSAPublic(byte[] data, String fileName) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException,
                InvalidKeySpecException {

        // Read public key from specified file
        PublicKey publicKey = readPublicKey(fileName);

        // Generate an RSA cipher to encrypt data
        Cipher encryptionCipher = Cipher.getInstance("RSA");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptionCipher.doFinal(data);
    }

    public static byte[] encryptRSAPrivate(byte[] data, String fileName) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException,
                InvalidKeySpecException {

        // Read private key from specified file
        PrivateKey privateKey = readPrivateKey(fileName);

        // Generate an RSA cipher to encrypt data
        Cipher encryptionCipher = Cipher.getInstance("RSA");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return encryptionCipher.doFinal(data);
    }

    public static byte[] decryptRSAPrivate(byte[] data, String fileName) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidKeySpecException {

        // Read private key from specified file
        PrivateKey privateKey = readPrivateKey(fileName);

        // Generate an RSA cipher to decrypt data
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSAPublic(byte[] data, String fileName) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidKeySpecException {

        // Read public key from specified file
        PublicKey publicKey = readPublicKey(fileName);

        // Generate an RSA cipher to decrypt data
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static PublicKey readPublicKey(String fileName) throws IOException, ClassNotFoundException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        File file = new File(fileName);
        FileInputStream fis = new FileInputStream(file);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(fis));

        // Read in modulus and exponent as BigIntegers
        BigInteger m = (BigInteger) oin.readObject();
        BigInteger e = (BigInteger) oin.readObject();
        fis.close();
        oin.close();

        // Initialize key spec and generate RSA public key
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(keySpec);
    }

    private static PrivateKey readPrivateKey(String fileName) throws IOException, ClassNotFoundException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        File file = new File(fileName);
        FileInputStream fis = new FileInputStream(file);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(fis));

        // Read in modulus and exponent as BigIntegers
        BigInteger m = (BigInteger) oin.readObject();
        BigInteger e = (BigInteger) oin.readObject();
        fis.close();
        oin.close();

        // Initialize key spec and generate RSA private key
        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePrivate(keySpec);
    }

    public static byte[] generateHash(String type, String file) throws NoSuchAlgorithmException, IOException {

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

    // Indicates a compromised password received by the server
    public static class InvalidPasswordException extends Exception { }

    // Indicates failure during RSA decryption using a private key
    public static class RSAPrivateDecryptionException extends Exception {
        RSAPrivateDecryptionException(String msg) {
            super("RSA Decryption failed using private key: " + msg);
        }
    }

    // Indicates failure during RSA encryption using a private key
    public static class RSAPrivateEncryptionException extends Exception {
        RSAPrivateEncryptionException(String msg) {
            super("RSA Encryption failed using private key: " + msg);
        }
    }

    // Indicates a failure during RSA decryption using a public key
    public static class RSAPublicDecryptionException extends Exception {
        RSAPublicDecryptionException(String msg) {
            super("RSA Decryption failed using public key: " + msg);
        }
    }

    // Indicates a failure during RSA encryption using a public key
    public static class RSAPublicEncryptionException extends Exception {
        RSAPublicEncryptionException(String msg) {
            super("RSA Encryption failed using public key: " + msg);
        }
    }

    // Indicates a failure while hashing data
    public static class HashingException extends Exception {
        HashingException(String msg) {
            super("Hashing failed: " + msg);
        }
    }

    // Indicates a failure during AES decryption
    public static class AESDecryptionException extends Exception {
        AESDecryptionException(String msg) {
            super("AES Decryption failed: " + msg);
        }
    }

    // Indicates a failure during AES encryption
    public static class AESEncryptionException extends Exception {
        AESEncryptionException(String msg) {
            super("AES Encryption failed: " + msg);
        }
    }

    // Indicates a client is trying to connect to a closed socket
    public static class SocketException extends Exception {
        SocketException(String msg) {
            super("Socket failure: " + msg);
        }
    }
}

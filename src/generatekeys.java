import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Evan O'Connor (eco2116)
 * Network Security - Programming Assignment 1
 *
 * generatekeys.java
 *
 * Main function used to generate and write private and public keys to files
 *
 */
public class generatekeys {

    private static final int RSA_MODULUS = 2048;

    public static void validationFailure(String msg) {
        System.out.println(msg);
        System.out.println("Usage: java generatekeys <server or client>");
        System.exit(0);
    }

    public static void main(String[] args) {

        // Validate arguments
        if (args.length != 1) {
            validationFailure("Expected one argument.");
        } else if (!args[0].equals("server") && !args[0].equals("client")) {
            validationFailure("Expected argument 1 to be 'server' or 'client'.");
        }
        try {
            // Initialize KeyPairGenerator and generate private public key pairs
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(RSA_MODULUS);
            KeyPair kp = kpg.genKeyPair();

            KeyFactory fact = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
            RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

            // Save generated keys to files
            saveToFile(args[0] + "_public.key", pub.getModulus(), pub.getPublicExponent());
            saveToFile(args[0] + "_private.key", priv.getModulus(), priv.getPrivateExponent());
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Failed finding RSA key factory.");
            System.exit(0);
        } catch (IOException e) {
            System.out.println("Failed to generate RSA keys.");
            System.exit(0);
        } catch (InvalidKeySpecException e) {
            System.out.println("Failed to find valid key spec.");
            System.exit(0);
        }
    }

    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {

        // Save moduli and exponents to file using serialisation
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Failed writing keys to files.", e);
        } finally {
            System.out.println("New key generated and saved to: " + fileName);
            oout.close();
        }
    }
}

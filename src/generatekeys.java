import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class generatekeys {

    public static void validationFailure(String msg) {
        System.out.println(msg);
        System.out.println("Usage: java generatekeys <server or client>");
        System.exit(0);
    }

    //TODO: cite http://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
    public static void main(String[] args) {

        // Validate arguments
        if(args.length != 1) {
            validationFailure("Expected one argument.");
        }
        if (!args[0].equals("server") && !args[0].equals("client")) {
            validationFailure("Expected argument 1 to be server or client.");
        }
        try {
            // Generate 2048-bit modulus private public key pairs
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();

            KeyFactory fact = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
            RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

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

    public static void saveToFile(String fileName,
                           BigInteger mod, BigInteger exp) throws IOException {

        // Save moduli and exponents to file using serialisation
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Failed writing keys to files.", e);
        } finally {
            oout.close();
        }
    }
}

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class server {

    public final static int SOCKET_PORT = 13267;  // you may change this
    public final static String FILE_TO_RECEIVED = "test_new.txt";  // you may change this
    public final static int FILE_SIZE = 6022386;

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

        Socket socket = acceptSocket();

        // Generate or use existing public / private keys
        File pubFile = new File("server_public.txt");
        File privFile = new File("server_private.txt");
        KeyPair keyPair = generateRSAKeys();
        PrintWriter pw = null;
        if(!pubFile.exists()) {
            try {
                System.out.println("Generating new server public key");
                pubFile.createNewFile();
                pw = new PrintWriter(pubFile);
                pw.print(keyPair.getPublic().toString());
                pw.close();
            } catch(IOException e) {
                failWithMessage("Failed to create public key file.");
                pw.close();
                System.exit(0);
            }
        }
        if(!privFile.exists()) {
            try {
                System.out.println("Generating new server private key");
                privFile.createNewFile();
                pw = new PrintWriter(privFile);
                pw.print(keyPair.getPrivate().getEncoded());
                pw.close();
            } catch(IOException e) {
                failWithMessage("Failed to create private key file.");
                pw.close();
                System.exit(0);
            }
        }
        receiveFile(socket);
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

    private static void receiveFile(Socket socket) {
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        // Receive the file from client
        try {
            int bytesRead;
            InputStream is;
            int current;
            byte[] myByteArray = new byte[FILE_SIZE];
            is = socket.getInputStream();
            fos = new FileOutputStream(FILE_TO_RECEIVED);
            bos = new BufferedOutputStream(fos);
            bytesRead = is.read(myByteArray, 0, myByteArray.length);
            current = bytesRead;
            do {
                bytesRead = is.read(myByteArray, current, (myByteArray.length - current));
                if (bytesRead >= 0) current += bytesRead;
            } while (bytesRead > -1);
            bos.write(myByteArray, 0, current);
            bos.flush();
            System.out.println("File " + FILE_TO_RECEIVED
                    + " downloaded (" + current + " bytes read)");
        } catch (FileNotFoundException e) {
            failWithMessage("File could not be found.");
        } catch (IOException e) {
            failWithMessage("Failed to receive file due to unexpected exception.");
        } finally {
            closeStreamsAndSocket(fos, bos, socket);
        }
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

    public static KeyPair generateRSAKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.genKeyPair();
        } catch(NoSuchAlgorithmException e) {
            failWithMessage("Failed to get instance of RSA key pair generator.");
        }
        return null;
    }
}
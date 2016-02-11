import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class server {

    public final static int SOCKET_PORT = 13267;  // you may change this
    public final static String FILE_TO_SEND = "/Users/evanoconnor/dev/security/programming1/test.txt";  // you may change this

    public static void main (String[] args) throws IOException {

        // Input and validate client parameters
        int port = validatePort(args[0]);
        String trustedMode = validateTrustMode()

        FileInputStream fis = null;
        BufferedInputStream bis = null;
        OutputStream os = null;
        ServerSocket servsock = null;
        Socket sock = null;
        try {
            servsock = new ServerSocket(SOCKET_PORT);
            while (true) {
                System.out.println("Waiting...");
                try {
                    sock = servsock.accept();
                    System.out.println("Accepted connection : " + sock);
                    // send file
                    File myFile = new File (FILE_TO_SEND);
                    byte [] mybytearray  = new byte [(int)myFile.length()];
                    fis = new FileInputStream(myFile);
                    bis = new BufferedInputStream(fis);
                    bis.read(mybytearray,0,mybytearray.length);
                    os = sock.getOutputStream();
                    System.out.println("Sending " + FILE_TO_SEND + "(" + mybytearray.length + " bytes)");
                    os.write(mybytearray,0,mybytearray.length);
                    os.flush();
                    System.out.println("Done.");
                }
                finally {
                    if (bis != null) bis.close();
                    if (os != null) os.close();
                    if (sock!=null) sock.close();
                }
            }
        }
        finally {
            if (servsock != null) servsock.close();
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
        System.exit(0);
    }

    // TODO: Validate RSA file names

    /**
     *  The port number on which the server will listen for a connection from the client.
     • mode: A single lowercase character of t or u. t means trusted mode, u means untrusted mode (file
     gets replaced).
     • Necessary RSA key components: any inputs (filenames) to provide the server the necessary
     information for the RSA keys . Key components should be read from files and not have to be typed
     by the user.
     Notes on the details
     */

}
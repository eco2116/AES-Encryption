import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

public class server {

    public final static int SOCKET_PORT = 13267;  // you may change this
    public final static String FILE_TO_RECEIVED = "test_new.txt";  // you may change this
    public final static int FILE_SIZE = 6022386;

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

        int bytesRead = 0;
        int current = 0;
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        InputStream is = null;
        Socket sock = null;
        ServerSocket servSock = null;

        System.out.println("Waiting...");
        try {
            servSock = new ServerSocket(SOCKET_PORT);
        } catch (IOException e) {
            failWithMessage("Unable to create server socket on port " + SOCKET_PORT);
        }
        try {
            sock = servSock.accept();
        } catch (UnknownHostException e) {
            failWithMessage("Failed to create socket due to unknown host.");
        } catch (IOException e) {
            failWithMessage("Failed to create socket.");
        }

        // receive file
        byte[] mybytearray = new byte[FILE_SIZE];

        try {
            is = sock.getInputStream();
        } catch (IOException e) {
            failWithMessage("Failure to get input stream from socket.", fos, bos, sock);
        }


        try {
            fos = new FileOutputStream(FILE_TO_RECEIVED);
        } catch (FileNotFoundException e) {
            failWithMessage("Failed to create file output stream because file was not found.", fos, bos, sock);
        }

        bos = new BufferedOutputStream(fos);

        try {
            bytesRead = is.read(mybytearray, 0, mybytearray.length);
        } catch (IOException e) {
            failWithMessage("Failed to read from input stream.", fos, bos, sock);
        }

        current = bytesRead;

        do {
            try {
                bytesRead = is.read(mybytearray, current, (mybytearray.length - current));
            } catch (IOException e) {
                failWithMessage("Failed to read from input stream.", fos, bos, sock);
            }

            if (bytesRead >= 0) current += bytesRead;
        } while (bytesRead > -1);

        try {
            bos.write(mybytearray, 0, current);
        } catch (IOException e) {
            failWithMessage("Failed to write to buffered output stream.", fos, bos, sock);
        }

        try {
            bos.flush();
        } catch (IOException e) {
            failWithMessage("Failed to flush buffered output stream", fos, bos, sock);
        }

        System.out.println("File " + FILE_TO_RECEIVED
                + " downloaded (" + current + " bytes read)");


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

    private static void failWithMessage(String msg, FileOutputStream fos, BufferedOutputStream bos, Socket sock) {
        System.out.println("Server-side error encountered.");
        System.out.println(msg);
        closeStreamsAndSocket(fos, bos, sock);
        System.exit(0);
    }

    private static void failWithMessage(String msg) {
        System.out.println("Server-side error encountered.");
        System.out.println(msg);
        System.exit(0);
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
}
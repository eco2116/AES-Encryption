import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;


// TODO: cite this: http://www.rgagnon.com/javadetails/java-0542.html
public class client {

    public final static int SOCKET_PORT = 13267;      // you may change this
    public final static String SERVER = "127.0.0.1";  // localhost
    public final static String
            FILE_TO_RECEIVED = "/Users/evanoconnor/dev/security/programming1/test.txt";  // you may change this, I give a
    // different name because i don't want to
    // overwrite the one used by server...

    public final static int FILE_SIZE = 6022386; // file size temporary hard coded
    // should bigger than the file to be downloaded

    public static void main (String[] args) {


        int bytesRead;
        int current = 0;
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        Socket sock = null;
        try {

            try {
                sock = new Socket(SERVER, SOCKET_PORT);
            } catch(UnknownHostException e) {
                failWithMessage("Could not create socket due to unknown host.");
            } catch(IOException e) {
                failWithMessage("Error creating socket. Unexpected IOException was thrown.");
            }

            System.out.println("Connecting...");

            // receive file
            byte [] mybytearray  = new byte [FILE_SIZE];

            try {
                InputStream is = sock.getInputStream();
            } catch()



            fos = new FileOutputStream(FILE_TO_RECEIVED);
            bos = new BufferedOutputStream(fos);
            bytesRead = is.read(mybytearray,0,mybytearray.length);
            current = bytesRead;

            do {
                bytesRead =
                        is.read(mybytearray, current, (mybytearray.length-current));
                if(bytesRead >= 0) current += bytesRead;
            } while(bytesRead > -1);

            bos.write(mybytearray, 0 , current);
            bos.flush();
            System.out.println("File " + FILE_TO_RECEIVED
                    + " downloaded (" + current + " bytes read)");
        }
        finally {
            closeStreamsAndSocket(fos, bos, sock);
        }
    }

    private static String validatePassword(String input) {
        if(input.length() != 16) {
            failWithMessage("Password must be 16 characters long.");
        } else if(!input.matches("[A-Za-z0-9]+")) {
            failWithMessage("Password must only contain alphanumeric characters.");
        }
        return input;
    }

    // TODO: validate file name

    private static String validateIP(String input) {
        // TODO: implement
        return input;
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

    private static void failWithMessage(String msg) {
        System.out.println("Client-side error encountered.");
        System.out.println(msg);
        System.exit(0);
    }

    private static void closeStreamsAndSocket(FileOutputStream fos, BufferedOutputStream bos, Socket sock) {
        try {
            if (fos != null) fos.close();
            if (bos != null) bos.close();
            if (sock != null) sock.close();
        } catch(IOException e) {
            failWithMessage("Unexpected IOException encountered while closing streams and sockets.");
        }

    }
/**
 * Password: The 16 character password may contain any alphanumeric character (i.e. lowercase,
 uppercase and digits). Note: special characters are not included in order to simplify the input.
 • filename: Clearly indicate in your README file if the path of the file provided as input must be the
 full path or relevant to the directory containing the executable. You may just require that the file be in
 the same directory as the executable.
 • server IP address or name
 • port number to use when contacting the server
 • Necessary RSA key components: any inputs (filenames) to provide the client the necessary
 information for the RSA keys . Key components should be read from files and not have to be typed
 by the user.
 */
}
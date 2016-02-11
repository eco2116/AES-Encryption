import java.io.*;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

public class client {

    public final static int SOCKET_PORT = 13267;      // you may change this
    public final static String SERVER = "127.0.0.1";  // localhost
    public final static String
            FILE_TO_SEND = "test.txt";  // you may change this, I give a
    // different name because i don't want to
    // overwrite the one used by server...



    public static void main (String[] args) {

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
//        String password = validatePassword(args[0]);
//        String filename = validateFileName(args[1]);
//        String address = validateIP(args[2]);
//        int port = validatePort(args[3]);

        FileInputStream fis = null;
        BufferedInputStream bis = null;
        OutputStream os = null;
        ServerSocket servsock = null;
        Socket sock = null;

        System.out.println("Connecting...");
        try {
            sock = new Socket(SERVER, SOCKET_PORT);
        } catch(IOException e) {
            failWithMessage("Failed to create socket.");
        }

        System.out.println("Accepted connection : " + sock);

        // send file
        File myFile = new File(FILE_TO_SEND);
        byte[] mybytearray = new byte[(int) myFile.length()];

        try {
            fis = new FileInputStream(myFile);
        } catch (FileNotFoundException e) {
            failWithMessage("File not found by name " + FILE_TO_SEND, fis, bis, sock, servsock);
        }

        bis = new BufferedInputStream(fis);

        try {
            bis.read(mybytearray, 0, mybytearray.length);
        } catch (IOException e) {
            failWithMessage("Failed to read buffered input stream.", fis, bis, sock, servsock);
        }

        try {
            os = sock.getOutputStream();
        } catch (IOException e) {
            failWithMessage("Failed to get output stream from socket.");
        }

        System.out.println("Sending " + FILE_TO_SEND + "(" + mybytearray.length + " bytes)");

        try {
            os.write(mybytearray, 0, mybytearray.length);
        } catch (IOException e) {
            failWithMessage("Failed to write to output stream.");
        }

        try {
            os.flush();
        } catch (IOException e) {
            failWithMessage("Failed to flush output stream.");
        }

        System.out.println("Done.");
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
    private static String validateFileName(String input) {
        return input;
    }

    // TODO: implement
    private static String validateIP(String input) {
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

    private static void failWithMessage(String msg, FileInputStream fis, BufferedInputStream bis, Socket sock, ServerSocket serverSock) {
        System.out.println("Client-side error encountered.");
        System.out.println(msg);
        closeStreamsAndSocket(fis, bis, sock, serverSock);
        System.exit(0);
    }

    private static void failWithMessage(String msg) {
        System.out.println("Client-side error encountered.");
        System.out.println(msg);
        System.exit(0);
    }

    private static void closeStreamsAndSocket(FileInputStream fis, BufferedInputStream bis, Socket sock, ServerSocket servSock) {
        try {
            if (fis != null) fis.close();
            if (bis != null) bis.close();
            if (sock != null) sock.close();
            if (servSock != null) servSock.close();
        } catch(IOException e) {
            failWithMessage("Failed to close streams and sockets.");
        }
    }
}
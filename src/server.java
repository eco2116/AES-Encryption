import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

public class server {

    public static void main(String argv[]) throws Exception {

        String clientMsg;

        // TODO: Input port
        ServerSocket serverSocket = new ServerSocket(6789);

        // TODO: handle break
        while(true) {

            Socket connection = serverSocket.accept();
            BufferedReader clientIn = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            DataOutputStream clientOut = new DataOutputStream(connection.getOutputStream());

            clientMsg = clientIn.readLine();
            System.out.println("receieved: " + clientMsg);

            clientOut.writeBytes("server receieved: " + clientMsg + "\n");
        }
    }

}
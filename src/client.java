import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.Socket;

public class client {

    public static void main(String argv[]) throws Exception {

        String msg;
        String response;

        BufferedReader clientIn = new BufferedReader(new InputStreamReader(System.in));
        Socket clientSocket = new Socket("localhost", 6789);
        DataOutputStream serverOut = new DataOutputStream(clientSocket.getOutputStream());
        BufferedReader serverIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        msg = clientIn.readLine();
        serverOut.writeBytes(msg);
        response = serverIn.readLine();
        System.out.println("I got from server: " + response);
        clientSocket.close();
    }
}

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;


public class Server {

    private static ServerSocket MyService;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        final CertificateAuthority ca = new CertificateAuthority();
        try {
            MyService = new ServerSocket(8820);
            System.out.println("Server is running");
            while (true) {
                Socket clientService = MyService.accept();
                DataInputStream input = new DataInputStream(clientService.getInputStream());
                DataOutputStream output = new DataOutputStream(clientService.getOutputStream());
                Thread clientThread = new Thread(new ClientHandler(clientService, input, output, ca));
                clientThread.start();
            }
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            if (MyService != null && !MyService.isClosed()) {
                try {
                    MyService.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}
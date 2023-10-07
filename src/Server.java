import java.io.*;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class Server {

    private static SSLServerSocket MyService;

    public static void main(String[] args) {

        try {
            SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            MyService = (SSLServerSocket) serverSocketFactory.createServerSocket(8888);
            System.out.println("Server is running");

            while (true) {
                SSLSocket clientService = (SSLSocket) MyService.accept();
                DataInputStream input = new DataInputStream(clientService.getInputStream());
                DataOutputStream output = new DataOutputStream(clientService.getOutputStream());
                Thread clientThread = new Thread(new CertificateAuthority(clientService, input, output));
                clientThread.start();
                System.out.println(input.readUTF());
                output.writeUTF("Connected");

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

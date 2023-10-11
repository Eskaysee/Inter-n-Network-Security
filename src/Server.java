import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Server {

    private static ServerSocket MyService;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        final CertificateAuthority ca = new CertificateAuthority();
        try {
            MyService = new ServerSocket(8820);
//            SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
//            MyService = (SSLServerSocket) serverSocketFactory.createServerSocket(8820);
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

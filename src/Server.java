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
import javax.net.ssl.SSLSocket;

public class Server {

    private static ServerSocket MyService;
    private static PublicKey myPublicKey;
    private static PrivateKey myPrivateKey;
    private static X509Certificate cert;

    private static KeyPair generateAsymKeys(String owner) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        try (FileOutputStream fosPub = new FileOutputStream(owner+".pub")) {
            fosPub.write(publicKey.getEncoded());
            fosPub.close();
            FileOutputStream fosPriv = new FileOutputStream(owner);
            fosPriv.write(privateKey.getEncoded());
            fosPriv.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return pair;
    }

    private static X509Certificate generateCert(String client, PublicKey clientPK) {
        X509Certificate cert;
        try {
            // Certificate subject and issuer names
            X500Name subject = new X500Name("CN="+client);
            X500Name issuer = new X500Name(
                    "CN=CA," +
                            "O=Certificate Authority"
            );

            // Certificate serial number
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

            Date notValidBefore = new Date();
            Date notValidAfter = new Date(notValidBefore.getTime() + 365 * 24 * 60 * 60 * 1000L); // 1 year validity

            // Key usage and extended key usage
            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);

            BasicConstraints basicConstraints = new BasicConstraints(true);

            // Create an X509v3 certificate builder
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    issuer,
                    serialNumber,
                    notValidBefore,
                    notValidAfter,
                    subject,
                    SubjectPublicKeyInfo.getInstance(clientPK.getEncoded())
            );

            // Set extensions
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, keyUsage);
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false, extendedKeyUsage);
            certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

            // Sign the certificate with the private key
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(myPrivateKey);
            X509CertificateHolder certificateHolder = certBuilder.build(signer);

            // Convert the certificate holder to an X509Certificate
            cert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try (FileOutputStream fos = new FileOutputStream(client+".pem");) {
            fos.write(cert.getEncoded());
            fos.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return cert;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        File caCert = new File("CA.pem");
        if (!caCert.exists()) {
            KeyPair kp = generateAsymKeys("CA");
            myPrivateKey = kp.getPrivate();
            myPublicKey = kp.getPublic();
            cert = generateCert("CA", myPublicKey);
        }
        try {
            MyService = new ServerSocket(8820);
//            SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
//            MyService = (SSLServerSocket) serverSocketFactory.createServerSocket(8820);
            System.out.println("Server is running");
            while (true) {
                Socket clientService = MyService.accept();
                DataInputStream input = new DataInputStream(clientService.getInputStream());
                DataOutputStream output = new DataOutputStream(clientService.getOutputStream());
                Thread clientThread = new Thread(new CertificateAuthority(clientService, input, output));
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

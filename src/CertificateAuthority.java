import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.math.BigInteger;
import javax.net.ssl.SSLSocket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class CertificateAuthority implements Runnable {

    private  X509Certificate[] certs;
    private  PublicKey myPublicKey;
    private  PrivateKey myPrivateKey;
    private  SSLSocket clientService;
    private  DataInputStream input;
    private  DataOutputStream output;
    private final Object fileLock = new Object();


    public CertificateAuthority(SSLSocket clientService, DataInputStream input, DataOutputStream output) {
        this.clientService = clientService;
        this.input = input;
        this.output = output;
        if (myPrivateKey == null || myPublicKey == null) {
            try {
                getKeys();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private synchronized byte[] readAllBytes (File file) {
        try {
            FileInputStream fis = new FileInputStream(file);
            byte[] fileBytes = new byte[(int) file.length()];
            fis.read(fileBytes);
            fis.close();
            return fileBytes;
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private  KeyPair generateAsymKeys(String owner) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        synchronized (fileLock) {
            try (FileOutputStream fosPub = new FileOutputStream(owner+".pub")) {
                fosPub.write(publicKey.getEncoded());
                fosPub.close();
                FileOutputStream fosPriv = new FileOutputStream(owner);
                fosPriv.write(privateKey.getEncoded());
                fosPriv.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return pair;
    }

    private  void getKeys() throws NoSuchAlgorithmException {
        File myPubKeyFile = new File("CA.pub");
        File myPrivKeyFile = new File("CA");
        try {
            if (myPubKeyFile.exists() && myPrivKeyFile.exists()){
                byte[] myPubBytes = readAllBytes(myPubKeyFile);
                byte[] myPrivBytes = readAllBytes(myPrivKeyFile);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                EncodedKeySpec myPubKeySpec = new X509EncodedKeySpec(myPubBytes);
                myPublicKey = keyFactory.generatePublic(myPubKeySpec);
                EncodedKeySpec myPrivKeySpec = new PKCS8EncodedKeySpec(myPrivBytes);
                myPrivateKey = keyFactory.generatePrivate(myPrivKeySpec);
            } else {
                KeyPair keyPair = generateAsymKeys("Alice");
                myPrivateKey = keyPair.getPrivate();
                myPublicKey = keyPair.getPublic();
            }
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private  X509Certificate generateCert(String client, PublicKey clientPK) {
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
        }
        synchronized (fileLock) {
            try (FileOutputStream fos = new FileOutputStream(client+".pem");) {
                fos.write(cert.getEncoded());
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            } catch (CertificateEncodingException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return cert;
    }

    @Override
    public void run() {
        try {
            while (!clientService.isClosed()){
                String request = input.readUTF();
                if (request.equals("Create Certificate")){
                    String client = input.readUTF();
                    byte[] digitalSignature = new byte[512];
                    input.read(digitalSignature);
                    byte[] clientKeyBytes = new byte[2048];
                    input.read(clientKeyBytes);
                    EncodedKeySpec myPubKeySpec = new X509EncodedKeySpec(clientKeyBytes);
                    PublicKey clientKey = KeyFactory.getInstance("RSA").generatePublic(myPubKeySpec);
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initVerify(clientKey);
                    generateCert(client, clientKey);
                }
            }
            System.out.println("Client Disconnected");
            output.close();
            input.close();
            clientService.close();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}

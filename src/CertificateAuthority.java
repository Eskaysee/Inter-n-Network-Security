import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class CertificateAuthority {
    private PublicKey myPublicKey;
    private PrivateKey myPrivateKey;
    private volatile Map<String, X509Certificate> certs;
    private static final Object lock = new Object();

    public CertificateAuthority() throws NoSuchAlgorithmException {
        certs = new HashMap<>();
        if (myPrivateKey == null || myPublicKey == null)
            getKeys("CA");
    }

    private KeyPair generateAsymKeys(String owner) throws NoSuchAlgorithmException {
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

    private void loadCerts() {
        File folder = new File(".");
        FilenameFilter pemFilter = (dir, name) -> name.endsWith(".pem");
        File[] certificateFiles = folder.listFiles(pemFilter);
        for (File crtFile : certificateFiles) {
            String name = crtFile.getName();
            name = name.substring(0, name.length()-4);
            try (FileInputStream fis = new FileInputStream(crtFile)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
                if (cert.getNotAfter().after(new Date()))
                    certs.put(name, cert);  //VALID
            } catch (FileNotFoundException | CertificateException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void getKeys(String name) throws NoSuchAlgorithmException {
        File caCert = new File(name+".pem");
        if (!caCert.exists()) {
            KeyPair kp = generateAsymKeys(name);
            myPrivateKey = kp.getPrivate();
            myPublicKey = kp.getPublic();
            generateCert(name, myPublicKey);
        } else {
            File myPubKeyFile = new File(name+".pub");
            File myPrivKeyFile = new File(name);
            try {
                byte[] myPubBytes = readAllBytes(myPubKeyFile);
                byte[] myPrivBytes = readAllBytes(myPrivKeyFile);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                EncodedKeySpec myPubKeySpec = new X509EncodedKeySpec(myPubBytes);
                myPublicKey = keyFactory.generatePublic(myPubKeySpec);
                EncodedKeySpec myPrivKeySpec = new PKCS8EncodedKeySpec(myPrivBytes);
                myPrivateKey = keyFactory.generatePrivate(myPrivKeySpec);
                loadCerts();
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private byte[] readAllBytes (File file) {
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

    public X509Certificate generateCert(String client, PublicKey clientPK) {
        X509Certificate cert;
        if (!certs.containsKey(client)) {
            X500Name subject = new X500Name("CN="+client);
            X500Name issuer = new X500Name(
                    "CN=CA," +
                            "O=Certificate Authority"
            );
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date notValidBefore = new Date();
            Date notValidAfter = new Date(notValidBefore.getTime() + 365 * 24 * 60 * 60 * 1000L); // 1 year validity
            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
            BasicConstraints basicConstraints;
            ExtendedKeyUsage extendedKeyUsage;
            if (client.equalsIgnoreCase("CA")) {
                basicConstraints = new BasicConstraints(true);
                extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);
            }
            else {
                basicConstraints = new BasicConstraints(false);
                extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
            }
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    issuer,
                    serialNumber,
                    notValidBefore,
                    notValidAfter,
                    subject,
                    SubjectPublicKeyInfo.getInstance(clientPK.getEncoded())
            );
            certBuilder.setIssuerUniqueID(new boolean[]{true,false,true,true,false});
            try {
                certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, keyUsage);
                DERSequence san;
                if (client.equalsIgnoreCase("CA")) {
                    san = new DERSequence(new GeneralName(GeneralName.iPAddress, "192.168.1.59"));
                    certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
                } else {
                    san = new DERSequence(new GeneralName(GeneralName.dNSName, "localhost"));
                    certBuilder.addExtension(Extension.basicConstraints, false, basicConstraints);
                }
                certBuilder.addExtension(Extension.subjectAlternativeName, false,san);
                certBuilder.addExtension(Extension.extendedKeyUsage, true, extendedKeyUsage);
                // Sign the certificate with the private key
                ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(myPrivateKey);
                X509CertificateHolder certificateHolder = certBuilder.build(signer);
                cert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
                synchronized (lock) {
                    FileOutputStream fos = new FileOutputStream(client+".pem");
                    fos.write(cert.getEncoded());
                    certs.put(client, cert);
                }
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            } catch (CertIOException e) {
                throw new RuntimeException(e);
            } catch (OperatorCreationException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            cert = certs.get(client); //Certs is the list of valid certificates
            if (cert.getNotAfter().after(new Date())) //checking if the certificate is expired
                System.out.println("Certificate Already Exists!");
            else {
                new File(client+".pem").delete();
                certs.remove(client);
                cert = generateCert(client, clientPK);
            }
        }
        return cert;
    }

    public synchronized boolean exists(String name) {
        return certs.containsKey(name);
    }

    public synchronized String[] certList() {
        int len = certs.size();
        return certs.keySet().toArray(new String[len]);
    }

}
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;
import java.util.Date;

public class EncryptMethods {

    public static PublicKey getKeyFromCert(String other, X509Certificate cert, PublicKey caPublicKey) throws NoSuchAlgorithmException {
        try {
            cert.checkValidity();
            if (caPublicKey != null) cert.verify(caPublicKey);
            String certName = cert.getSubjectX500Principal().getName().strip().substring(3);
            if (!certName.equalsIgnoreCase(other)) return null;
            return cert.getPublicKey();
        } catch (CertificateNotYetValidException e) {
            System.out.println("Certificate isn't valid yet.");
            return null;
        } catch (CertificateExpiredException e) {
            System.out.println("Certificate is expired.");
            return null;
        } catch (InvalidKeyException | SignatureException e) {
            System.out.println("Certificate Isn't From the Certificate Authority!");
            return null;
        } catch (CertificateException e) {
            System.out.println("Faulty Certificate (Corrupted)");
            return null;
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private static String hash(String message) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] mssgBytes = message.getBytes();
        byte[] hashed = sha256.digest(mssgBytes);
        StringBuilder  hexString = new StringBuilder();
        for (byte b : hashed) {
            String hex = String.format("%02x", b);
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static String signHash(String message, PrivateKey myPrivateKey) throws NoSuchAlgorithmException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);
            byte[] signedMssg = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(signedMssg);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static String encrypt(String message, SecretKey sessionKey, IvParameterSpec iv) throws NoSuchAlgorithmException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, iv);
            byte[] cipherText = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static String encrypt(SecretKey sessionKey, PublicKey otherPublicKey) throws NoSuchAlgorithmException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, otherPublicKey);
            byte[] encryptedSK = cipher.doFinal(sessionKey.getEncoded());
            return Base64.getEncoder().encodeToString(encryptedSK);
        } catch (BadPaddingException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey decrypt(String encryptedMssg, PrivateKey myPrivateKey) throws NoSuchAlgorithmException {
        byte[] encryptedMssgBytes= Base64.getDecoder().decode(encryptedMssg);
        try {
            Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
            byte[] decryptedSK = decipher.doFinal(encryptedMssgBytes);
            SecretKey sessionKey = new SecretKeySpec(decryptedSK, "AES");
            return sessionKey;
        } catch (BadPaddingException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static String decrypt(String cipheredMessage, SecretKey sessionKey, IvParameterSpec iv) throws NoSuchAlgorithmException {
        byte[] cyBytes = Base64.getDecoder().decode(cipheredMessage);
        try {
            Cipher decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, sessionKey, iv);
            byte[] plainText = decipher.doFinal(cyBytes);
            return new String(plainText);
        } catch (NoSuchPaddingException | BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException | InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public static Boolean verifySender(String signedMssg, PublicKey sendersKey) throws NoSuchAlgorithmException {
        byte[] signedMbytes = Base64.getDecoder().decode(signedMssg);
        try {
            Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decipher.init(Cipher.DECRYPT_MODE, sendersKey);
            byte[] unsignedMssg = decipher.doFinal(signedMbytes);
            return true;
        } catch (BadPaddingException | NoSuchPaddingException e) {
            return false;
        } catch (IllegalBlockSizeException | InvalidKeyException e) {
            return false;
        }
    }

    private static String hash2(String message) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] mssgBytes = message.getBytes();
        byte[] hashed = sha256.digest(mssgBytes);
        StringBuilder  hexString = new StringBuilder();
        for (byte b : hashed) {
            String hex = String.format("%02x", b);
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static boolean compareHash(String message) throws NoSuchAlgorithmException {
        String firstHash = hash(message);
        String secondHash = hash2(message);
        return secondHash.equals(firstHash);
    }

    public static X509Certificate generateCert(String client, PublicKey clientPK, PrivateKey myPrivateKey) {
        X509Certificate cert;
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
            if (client.equalsIgnoreCase("CA")) {
                certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, basicConstraints);
            } else {
                certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, false, basicConstraints);
            }
            certBuilder.addExtension(Extension.extendedKeyUsage, true, extendedKeyUsage);
            // Sign the certificate with the private key
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(myPrivateKey);
            X509CertificateHolder certificateHolder = certBuilder.build(signer);
            cert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return cert;
    }

}
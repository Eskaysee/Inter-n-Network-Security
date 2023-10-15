import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.cert.X509Certificate;

public class EncryptMethodsTest {
    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static KeyPair generateAsymKeys(String owner) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        return pair;
    }

    private static SecretKey generateSymKeys(String name1, String name2) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey symKey = generator.generateKey();
        return symKey;
    }

    @Test
    public void getKeyFromCert() throws NoSuchAlgorithmException {
        KeyPair kp = generateAsymKeys("Me");
        KeyPair caKP = generateAsymKeys("CA");
        X509Certificate cert = EncryptMethods.generateCert("Me", kp.getPublic(), caKP.getPrivate());
        PublicKey myPubK2 = EncryptMethods.getKeyFromCert("Me", cert, caKP.getPublic());
        Assertions.assertEquals(kp.getPublic(), myPubK2);
    }

    @Test
    public void sessionKeyDecrypt() throws NoSuchAlgorithmException {
        SecretKey session = generateSymKeys("M","e");
        KeyPair kp = generateAsymKeys("Me");
        String cipheredKey = EncryptMethods.encrypt(session, kp.getPublic());
        SecretKey seshKey = EncryptMethods.decrypt(cipheredKey, kp.getPrivate());
        Assertions.assertEquals(session,seshKey);
    }

    @Test
    public void testDecrypt() throws NoSuchAlgorithmException {
        IvParameterSpec iv = generateIv();
        SecretKey seshKey = generateSymKeys("M","e");
        String encryptedMssg = EncryptMethods.encrypt("Test", seshKey, iv);
        String decryptedMssg = EncryptMethods.decrypt(encryptedMssg, seshKey, iv);
        Assertions.assertEquals("Test", decryptedMssg);
    }

    @Test
    public void verifySender() throws NoSuchAlgorithmException {
        KeyPair kp = generateAsymKeys("Me");
        String signedMssg = EncryptMethods.signHash("Testing", kp.getPrivate());
        Assertions.assertTrue(EncryptMethods.verifySender(signedMssg, kp.getPublic()));
    }

    @Test
    public void compareHash() throws NoSuchAlgorithmException {
        Assertions.assertTrue(EncryptMethods.compareHash("Experiment"));
    }
}
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.cert.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Client {

    private static Socket MyClient;
    private static DataInputStream input;
    private static DataOutputStream output;

    private static PublicKey myPublicKey;
    private static PrivateKey myPrivateKey;
    private static X509Certificate cert;
    private static SecretKey sessionKey;
    private static PublicKey bobPublicKey;
    static final IvParameterSpec iv = generateIv();

    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    
    private static byte[] readAllBytes (File file) {
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
    
    private static SecretKey generateSymKeys() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        SecretKey symKey = generator.generateKey();
        try (FileOutputStream fos = new FileOutputStream("session.key")) {
            fos.write(symKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return symKey;
    }
    
    private static void getKeys(String name) throws NoSuchAlgorithmException {
        File myPubKeyFile = new File(name+".pub");
        File myPrivKeyFile = new File(name);
        File seshKeyFile = new File("session.key");
        File bobPubKeyFile = new File("Bob.pub");
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
                KeyPair keyPair = generateAsymKeys(name);
                myPrivateKey = keyPair.getPrivate();
                myPublicKey = keyPair.getPublic();
                //Send to CA to CREATE Certificate
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(myPrivateKey);
                signature.update(name.getBytes());
                SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket caClient = (SSLSocket) sslSocketFactory.createSocket("192.168.1.55", 8888);
                caClient.startHandshake();
                DataInputStream caIn = new DataInputStream(caClient.getInputStream());
                DataOutputStream caOut = new DataOutputStream(caClient.getOutputStream());
                caOut.writeUTF("Create Certificate");
                caOut.writeUTF(name);
                caOut.write(signature.sign());
                caOut.write(myPublicKey.getEncoded());
                //
            }
            if (bobPubKeyFile.exists()) {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                byte[] bobPubBytes = readAllBytes(bobPubKeyFile);
                EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(bobPubBytes);
                bobPublicKey = keyFactory.generatePublic(bobPubKeySpec);
            } else {
                //
            }
            if (seshKeyFile.exists()){
                byte[] seshBytes = readAllBytes(seshKeyFile);
                sessionKey = new SecretKeySpec(seshBytes, "AES");
            } else {
                sessionKey = generateSymKeys();
                establishComms();
            }
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    //sending
    private static String hash(String folderName, String imageName) throws NoSuchAlgorithmException {
        File image = new File(folderName+"/"+imageName);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        try {
            byte[] imageBytes = readAllBytes(image);
            byte[] hashed = sha256.digest(imageBytes);
            StringBuilder  hexString = new StringBuilder();
            for (byte b : hashed) {
                String hex = String.format("%02x", b);
                hexString.append(hex);
            }
            FileWriter file = new FileWriter(folderName+"/Image Hash.txt");
            file.write(hexString.toString());
            file.close();
            return hexString.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void signHash(String folderName, String image, PrivateKey aPrivateKey) throws NoSuchAlgorithmException {
        Cipher cipher = null;
        String hash = hash(folderName,image);
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aPrivateKey);
            byte[] signedHash = cipher.doFinal(hash.getBytes());
            FileOutputStream stream = new FileOutputStream(folderName+"/Image Hash.txt");
            stream.write(signedHash);
            stream.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean compressFiles(String[] files, String zipName) {
        String[] filesToCompress = files;
        String compressedFileName = zipName;
        try (FileOutputStream fos = new FileOutputStream(compressedFileName);
             ZipOutputStream zipOut = new ZipOutputStream(fos)) {
            for (String fileToCompress : filesToCompress) {
                File file = new File(fileToCompress);
                FileInputStream fis = new FileInputStream(file);
                ZipEntry zipEntry = new ZipEntry(file.getName());
                zipOut.putNextEntry(zipEntry);
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    zipOut.write(buffer, 0, bytesRead);
                }
                fis.close();
            }
            zipOut.close();
            fos.close();
            return  true;
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void encrypt(File zipFile, SecretKey sessionKey, IvParameterSpec iv) throws NoSuchAlgorithmException {
        Cipher cipher = null;
        try {
            byte[] zipBytes = readAllBytes(zipFile);
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, iv);
            byte[] cipherText = cipher.doFinal(zipBytes);
            //Overwrite the zip file
            FileOutputStream  stream = new FileOutputStream(zipFile);
            stream.write(cipherText);
            stream.close();
        } catch (FileNotFoundException | BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (IOException | NoSuchPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static void encrypt(SecretKey sessionKey, PublicKey bobPublicKey) throws NoSuchAlgorithmException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, bobPublicKey);
            byte[] encryptedSK = cipher.doFinal(sessionKey.getEncoded());
            //Overwrite the zip file
            FileOutputStream  stream = new FileOutputStream("session.key");
            stream.write(encryptedSK);
            stream.close();
        } catch (BadPaddingException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static String sendFile(String fileName) {
        System.out.printf("Sending file %s\n", fileName);
        File file = new File(fileName);
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            int bytesRead = 0;
            output.writeUTF(fileName);
            output.writeLong(file.length());
            // Here we  break file into chunks
            byte[] buffer = new byte[4 * 1024];
            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                // Send the file to Server Socket
                output.write(buffer, 0, bytesRead);
            }
            output.flush();
            // close the file here
            fileInputStream.close();
            return "Server response: " + input.readUTF();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //receive
    private static String receiveFile(String fileName) {
        int bytesRead = 0;
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(fileName);
            long fileSize = input.readLong(); // read file size
            byte[] buffer = new byte[4 * 1024];
            while (fileSize > 0 && (bytesRead = input.read(buffer,0, (int)Math.min(buffer.length, fileSize))) != -1) {
                // Here we write the file using write method
                fileOutputStream.write(buffer, 0, bytesRead);
                fileSize -= bytesRead; // read upto file size
            }
            // Here we received file
            fileOutputStream.close();
            return "Files received";
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    private static void decrypt(String encryptedSKname, PrivateKey bPrivateKey) throws NoSuchAlgorithmException {
        File encryptedSK= new File(encryptedSKname);
        byte[] skBytes = readAllBytes(encryptedSK);
        try {
            Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decipher.init(Cipher.DECRYPT_MODE, bPrivateKey);
            byte[] decryptedSK = decipher.doFinal(skBytes);
            FileOutputStream fos = new FileOutputStream(encryptedSK);
            fos.write(decryptedSK);
            fos.close();
            sessionKey = new SecretKeySpec(decryptedSK, "AES");
        } catch (BadPaddingException | NoSuchPaddingException e) {
            System.out.println("Incorrect Key Buddy!");
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void decrypt(String cipheredMessage, SecretKey sessionKey, String initVec) throws NoSuchAlgorithmException {
        File encryptedZip = new File(cipheredMessage+".zip");
        byte[] skBytes = readAllBytes(encryptedZip);
        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(initVec));
        //INCOMPLETE
        try {
            Cipher decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, sessionKey, iv);
            byte[] plainText = decipher.doFinal(skBytes);
            FileOutputStream fos = new FileOutputStream(encryptedZip);
            fos.write(plainText);
            fos.close();
        } catch (NoSuchPaddingException | BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException | InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException | FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean decompressFiles(String zipName) {
        // Create a directory to store decompressed files
        File outputDirectory = new File(zipName);
        outputDirectory.mkdirs();
        // Receive and decompress the file
        try (FileInputStream fis = new FileInputStream(zipName+".zip");
             ZipInputStream zipIn = new ZipInputStream(fis)) {
            ZipEntry entry;
            while ((entry = zipIn.getNextEntry()) != null) {
                String entryName = entry.getName();
                File file = new File(outputDirectory, entryName);
                FileOutputStream fosEntry = new FileOutputStream(file);
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = zipIn.read(buffer)) != -1) {
                    fosEntry.write(buffer, 0, bytesRead);
                }
                fosEntry.close();
            }
            zipIn.close();
            fis.close();
            return true;
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean verifySender(String hashFile, PublicKey sendersKey) throws NoSuchAlgorithmException {
        File signedHashFile = new File(hashFile);
        byte[] signedHashBytes = readAllBytes(signedHashFile);
        try {
            Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decipher.init(Cipher.DECRYPT_MODE, sendersKey);
            byte[] decryptedSK = decipher.doFinal(signedHashBytes);
            FileOutputStream fos = new FileOutputStream(signedHashFile);
            fos.write(decryptedSK);
            fos.close();
            return true;
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException | NoSuchPaddingException e) {
            return false;
        } catch (IllegalBlockSizeException | InvalidKeyException e) {
            return false;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static String hash2(String folderName, File image) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        try {
            byte[] imageBytes = readAllBytes(image);
            byte[] hashed = sha256.digest(imageBytes);
            StringBuilder  hexString = new StringBuilder();
            for (byte b : hashed) {
                String hex = String.format("%02x", b);
                hexString.append(hex);
            }
            FileWriter file = new FileWriter(folderName+"/Hashed Picture.txt");
            file.write(hexString.toString());
            file.close();
            return hexString.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean compareHash(String folderName, String imageName) throws NoSuchAlgorithmException {
        File image = new File(imageName);
        String secondHash = hash2(folderName, image);
        String firstHash = "";
        try {
            Scanner hash1 = new Scanner(new File(folderName+"/Image Hash.txt"));
            while (hash1.hasNext()) firstHash += hash1.nextLine();
            hash1.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        return secondHash.equals(firstHash);
    }

    private static void establishComms() throws NoSuchAlgorithmException {
        File dir = new File("EstComms");
        dir.mkdir();
        String plaintext = "Hi Bob, it's Alice.\nPlease send me Pictures/Images?\nMuch appreciated, thanks!";
        try {
            FileWriter file = new FileWriter(dir.getName()+"/First Request.txt");
            file.write(plaintext);
            file.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        //encrypt
        signHash(dir.getName(), "First Contact.txt", myPrivateKey);
        compressFiles(new String[]{dir.getName()+"/Image Hash.txt",dir.getName()+"/First Contact.txt"}, dir.getName()+".zip");
        File zip1stRequest = new File(dir.getName()+".zip");
        encrypt(zip1stRequest, sessionKey, iv);
        encrypt(sessionKey, bobPublicKey);
        String ivAsString = Base64.getEncoder().encodeToString(iv.getIV());
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        try {
            if (myPrivateKey == null || myPublicKey == null) getKeys("Alice");
            final IvParameterSpec iv = generateIv();
            //Connect to Bob
            MyClient = new Socket("192.168.1.55", 8888); //machine IP & Port number for service > 1023
            input = new DataInputStream(MyClient.getInputStream());
            output = new DataOutputStream(MyClient.getOutputStream());

            //

            MyClient.shutdownInput();
            MyClient.shutdownOutput();
            input.close();
            output.close();
            MyClient.close();
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
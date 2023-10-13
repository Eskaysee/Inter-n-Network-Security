import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.SocketException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.net.Socket;
import javax.net.ssl.*;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Client {

    private static SSLSocket MyClient;
    private static SSLServerSocket MyService;
    private static DataInputStream input;
    private static DataOutputStream output;

    private static PublicKey myPublicKey;
    private static PrivateKey myPrivateKey;
    private static PublicKey caPublicKey;
    private static SecretKey sessionKey;
    private static PublicKey otherPublicKey;
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

    private static SecretKey generateSymKeys(String name1, String name2) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        SecretKey symKey = generator.generateKey();
        try (FileOutputStream fos = new FileOutputStream(name1+name2+"Session.key")) {
            fos.write(symKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return symKey;
    }

    private static void getKeys(String name) throws NoSuchAlgorithmException {
        File myPubKeyFile = new File(name+".pub");
        File myPrivKeyFile = new File(name);
        try {
            if (myPubKeyFile.exists() && myPrivKeyFile.exists()){
                byte[] myPubBytes = readAllBytes(myPubKeyFile);
                byte[] myPrivBytes = readAllBytes(myPrivKeyFile);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                EncodedKeySpec myPubKeySpec = new X509EncodedKeySpec(myPubBytes);
                myPublicKey = keyFactory.generatePublic(myPubKeySpec);
                EncodedKeySpec myPrivKeySpec = new PKCS8EncodedKeySpec(myPrivBytes);
                myPrivateKey = keyFactory.generatePrivate(myPrivKeySpec);
                caPublicKey = getKeyFromCert(name,"CA");
            } else {
                KeyPair keyPair = generateAsymKeys(name);
                myPrivateKey = keyPair.getPrivate();
                myPublicKey = keyPair.getPublic();
                //Send to CA to CREATE Certificate
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(myPrivateKey);
                signature.update(name.getBytes());
                Socket caClient = new Socket("192.168.1.59", 8820);
                input = new DataInputStream(caClient.getInputStream());
                output = new DataOutputStream(caClient.getOutputStream());
                output.writeUTF("New client connected to Server!");
                System.out.println(input.readUTF());

                output.writeUTF("Certificate Signing Request");
                Client.output.writeUTF(receiveFile("CA.pem"));
                caPublicKey = getKeyFromCert(name,"CA");
                System.out.println("Sending Certificate Signing Request");
                output.writeUTF(name);
                output.write(signature.sign());
                output.write(myPublicKey.getEncoded());
                if (!input.readBoolean()){
                    System.out.println("CA failed to create certificate. " +
                            "Signature didn't match the public key sent. Trying again...");
                    myPrivKeyFile.delete(); myPubKeyFile.delete();
                    caClient.shutdownInput(); caClient.shutdownOutput();
                    input.close(); output.close(); caClient.close();
                    getKeys(name);
                }
                System.out.println("Approved");
                Client.output.writeUTF(receiveFile(name+".pem"));
                output.writeUTF("Disconnected");
                caClient.shutdownInput(); caClient.shutdownOutput();
                input.close(); output.close(); caClient.close();
                System.out.println("Disconnected From CA Server");
            }
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate loadCert(String name) {
        try (FileInputStream fis = new FileInputStream(name+".pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        } catch (CertificateException | FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey getKeyFromCert(String name, String other) throws NoSuchAlgorithmException {
        try (FileInputStream fis = new FileInputStream(other+".pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            cert.checkValidity();
            if (caPublicKey != null) cert.verify(caPublicKey);
            return cert.getPublicKey();
        } catch (FileNotFoundException e) {
            System.out.println("Don't have "+other+"'s Certificate.");
            System.out.println("Checking with the Certificate Authority...");
            if (requestOthersKey(name, other)) return otherPublicKey;
            else return null;
        } catch (CertificateNotYetValidException e) {
            System.out.println("Certificate isn't valid yet");
            return null;
        } catch (CertificateExpiredException e) {
            System.out.println("Certificate is expired checking the Certificate Authority for an updated version");
            if (requestOthersKey(name, other)) return otherPublicKey;
            else return null;
        } catch (SignatureException | InvalidKeyException e) {
            System.out.println("Certificate Isn't From the Certificate Authority!");
            return null;
        } catch (CertificateException e) {
            System.out.println("Faulty Certificate (Corrupted)");
            File file = new File(other+".pem");
            file.delete();
            System.out.println("Deleting the stored certificate and requesting from Certificate Authority");
            if (requestOthersKey(name, other)) return otherPublicKey;
            else return null;
        } catch (IOException | NoSuchProviderException e) {
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

    private static void encrypt(SecretKey sessionKey, PublicKey otherPublicKey, String seshKeyFileName) throws NoSuchAlgorithmException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, otherPublicKey);
            byte[] encryptedSK = cipher.doFinal(sessionKey.getEncoded());
            //Overwrite the zip file
            FileOutputStream  stream = new FileOutputStream(seshKeyFileName);
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

    private static void sendSeshKey(String from, String to) throws NoSuchAlgorithmException {
        File dir = new File("EstComms");
        dir.mkdir();
        String plaintext = "Hi "+to+", it's "+from+".\n" +
                "I've sent you a session key ("+from+to+"Session.key) for us to use in future communications.\n" +
                "I look forward to hearing from you!";
        try {
            FileWriter file = new FileWriter(dir.getName()+"/First Contact.txt");
            file.write(plaintext);
            file.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        signHash(dir.getName(), "First Contact.txt", myPrivateKey);
        compressFiles(new String[]{dir.getName()+"/Image Hash.txt",dir.getName()+"/First Contact.txt"}, dir.getName()+".zip");
        File zip1stContact = new File(dir.getName()+".zip");
        encrypt(zip1stContact, sessionKey, iv);
        encrypt(sessionKey, otherPublicKey, from+to+"Session.key");
        String ivAsString = Base64.getEncoder().encodeToString(iv.getIV());
//        sendFile(from+to+"Session.key");

        ///
        SSLContext ctx = getSSLContext(from);
        System.setProperty("javax.net.ssl.keyStore", from+"keystore.jks");
        System.setProperty("javax.net.ssl.trustStore", "CAtruststore.jks");
        try {
            SSLSocketFactory sslSocketFactory =  ctx.getSocketFactory();
            MyClient = (SSLSocket) sslSocketFactory.createSocket("localhost", 8200);
            input = new DataInputStream(MyClient.getInputStream());
            output = new DataOutputStream(MyClient.getOutputStream());

            System.out.println();
            output.writeUTF("Connected");
            System.out.println(to+" response: "+input.readUTF());

            System.out.println(to+" response: "+input.readUTF());
            output.writeUTF("Disconnecting");
            System.out.println();

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

    private static SSLContext getSSLContext(String myName) throws NoSuchAlgorithmException {
        SSLContext ctx = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            KeyStore trustStore = KeyStore.getInstance("JKS");
            ks.load(null,null);
            trustStore.load(null,null);
            X509Certificate myCert = loadCert(myName);
            ks.setKeyEntry(myName, myPrivateKey, "".toCharArray(), new Certificate[]{myCert, loadCert("CA")});
            trustStore.setCertificateEntry("CA", loadCert("CA"));
            ks.setCertificateEntry("CA", loadCert("CA"));
            FileOutputStream keyStore = new FileOutputStream(myName+"keystore.jks");
            ks.store(keyStore,"".toCharArray());
            FileOutputStream trustCAStore = new FileOutputStream("CAtruststore.jks");
            trustStore.store(trustCAStore, "".toCharArray());
            kmf.init(ks, "".toCharArray());
            tmf.init(trustStore);
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
        return ctx;
    }

    //receive
    private static String receiveFile(String fileName) {
        int bytesRead = 0;
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(fileName);
            long fileSize = input.readLong(); // read file size
            byte[] buffer = new byte[4 * 1024];
            while (fileSize > 0 && (bytesRead = input.read(buffer,0, (int)Math.min(buffer.length, fileSize))) != -1) {
                fileOutputStream.write(buffer, 0, bytesRead);
                fileSize -= bytesRead; // read upto file size
            }
            // Here we received file
            fileOutputStream.close();
            System.out.println(fileName+" received");
            return fileName+" received";
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

    private static boolean connect(String from, String to) throws NoSuchAlgorithmException {
        File otherCertFile = new File(to+".pem");
        File seshKeyFile = new File(from+to+"Session.key");
        File seshKeyFileAlt = new File(to+from+"Session.key");
        boolean firstContact = false;
        otherPublicKey = getKeyFromCert(from, to);
        if (otherPublicKey==null) {
            System.out.println("Enter another name to contact or...\n" +
                    "Type \"menu\" and hit enter to return to the main menu");
            return false;
        }
        if (seshKeyFile.exists()){
            byte[] seshBytes = readAllBytes(seshKeyFile);
            sessionKey = new SecretKeySpec(seshBytes, "AES");
        } else if (seshKeyFileAlt.exists()) {
            byte[] seshBytes = readAllBytes(seshKeyFileAlt);
            sessionKey = new SecretKeySpec(seshBytes, "AES");
        } else {
            sessionKey = generateSymKeys(from, to);
            firstContact = true;
        }
        if (firstContact) sendSeshKey(from, to);
        return true;
    }

    private static boolean requestOthersKey(String name, String other) throws NoSuchAlgorithmException {
        try {
            Socket caClient = new Socket("192.168.1.59", 8820);
            input = new DataInputStream(caClient.getInputStream());
            output = new DataOutputStream(caClient.getOutputStream());
            Client.output.writeUTF("New client connected to Server!");
            System.out.println(Client.input.readUTF());
            //
            System.out.println("Requesting "+other+"'s Certificate");
            output.writeUTF("Requesting Certificate");
            output.writeUTF(name);
            output.writeUTF(other);
            boolean found = input.readBoolean();
            if (found) {
                Client.output.writeUTF(receiveFile(other+".pem"));
                otherPublicKey = getKeyFromCert(name, other);
            }
            else {
                System.out.println("Certificate doesn't exist!");
                System.out.println("The following are available though:");
                int i = input.readInt();
                for (int j=0; j<i; j++) {
                    String person = input.readUTF();
                    if (!person.equals("CA")&&!person.equals(name))
                        System.out.println(person);
                }
            }
            output.writeUTF("Disconnected");
            caClient.shutdownInput(); caClient.shutdownOutput();
            input.close(); output.close(); caClient.close();
            System.out.println("Disconnected From CA Server");
            return found;
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner consoleIn = new Scanner(System.in);
        boolean running = true;
        System.out.println("What's your name?");
        String myName = consoleIn.nextLine().strip();
        if (myPrivateKey == null || myPublicKey == null) getKeys(myName);
        System.out.println();
        do {
            System.out.println("What do you want to do?\nEnter the corresponding number:\n" +
                    "1. Contact Someone\n" +
                    "2. Wait (2 mins) to be Contacted\n" +
                    "3. Quit");
            int response = consoleIn.nextInt();
            consoleIn.nextLine();
            switch (response) {
                case 1: {
                    System.out.println("Who do you want to contact?");
                    String otherName = consoleIn.nextLine().strip();
                    if (otherPublicKey == null) {
                        while (!connect(myName, otherName)) {
                            otherName = consoleIn.nextLine().strip();
                            if (otherName.equalsIgnoreCase("menu")) break;
                            otherName = otherName.substring(0, 1).toUpperCase() + otherName.substring(1).toLowerCase();
                        }
                    }
                    if (otherName.equalsIgnoreCase("menu")) {
                        System.out.println();
                        break;
                    }
                    ///Send or request
                    break;
                }
                case 2: {
                    System.out.println("Who are you expecting contact from?");
                    String otherName = consoleIn.nextLine().strip();
                    otherPublicKey = getKeyFromCert(myName, otherName);
                    while (otherPublicKey == null) {
                        System.out.println("Enter another name to contact them\n" +
                                "or type \"menu\" and hit enter to return to the main menu");
                        otherName = consoleIn.nextLine().strip();
                        if (otherName.equalsIgnoreCase("menu")) break;
                        otherPublicKey = getKeyFromCert(myName, otherName);
                    }
                    if (otherName.equalsIgnoreCase("menu")) {
                        System.out.println();
                        break;
                    }

                    SSLContext ctx = getSSLContext(myName);
                    System.setProperty("javax.net.ssl.keyStore", myName+"keystore.jks");
                    System.setProperty("javax.net.ssl.trustStore", "CAtruststore.jks");
                    try {
                        SSLServerSocketFactory serverSocketFactory = ctx.getServerSocketFactory();
                        MyService = (SSLServerSocket) serverSocketFactory.createServerSocket(8200);
                        MyService.setSoTimeout(2*60*1000);
                        MyClient = (SSLSocket) MyService.accept();
                        input = new DataInputStream(MyClient.getInputStream());
                        output = new DataOutputStream(MyClient.getOutputStream());

                        System.out.println();
                        System.out.println(otherName+" response: "+input.readUTF());
                        output.writeUTF("Connected");

                        output.writeUTF("Disconnecting");
                        System.out.println(otherName+" response: "+input.readUTF());
                        System.out.println();

//                        while (!MyClient.isClosed()){
//                            String request = input.readUTF();
//                        }
                        input.close();
                        output.close();
                        MyClient.close();
                    } catch (SocketException e) {
                        throw new RuntimeException(e);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                case 3:
                    running = false;
            }
        } while (running);
    }
}
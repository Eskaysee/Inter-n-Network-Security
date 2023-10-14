import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Client {

    private static Socket MyClient;
    private static DataInputStream input;
    private static DataOutputStream output;
    private static String myName;
    private static PublicKey myPublicKey;
    private static PrivateKey myPrivateKey;
    private static PublicKey caPublicKey;
    private static SecretKey sessionKey;
    private static IvParameterSpec iv;
    private static PublicKey otherPublicKey;

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
        generator.init(256);
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
                caPublicKey = getKeyFromCert("CA");
            } else {
                KeyPair keyPair = generateAsymKeys(name);
                myPrivateKey = keyPair.getPrivate();
                myPublicKey = keyPair.getPublic();
                //Send to CA to CREATE Certificate
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(myPrivateKey);
                signature.update(name.getBytes());
                MyClient = new Socket("192.168.1.59", 8820);
                input = new DataInputStream(MyClient.getInputStream());
                output = new DataOutputStream(MyClient.getOutputStream());
                output.writeUTF("New client connected to Server!");
                System.out.println(input.readUTF());

                output.writeUTF("Certificate Signing Request");
                output.writeUTF(receiveFile("CA.pem"));
                caPublicKey = getKeyFromCert("CA");
                System.out.println("Sending Certificate Signing Request");
                output.writeUTF(name);
                output.write(signature.sign());
                output.write(myPublicKey.getEncoded());
                if (!input.readBoolean()){
                    System.out.println("CA failed to create certificate. " +
                            "Signature didn't match the public key sent. Trying again...");
                    myPrivKeyFile.delete(); myPubKeyFile.delete();
                    output.writeUTF("Disconnected");
                    MyClient.shutdownInput(); MyClient.shutdownOutput();
                    input.close(); output.close(); MyClient.close();
                    getKeys(name);
                }
                System.out.println("Approved");
                output.writeUTF(receiveFile(name+".pem"));
                output.writeUTF("Disconnected");
                MyClient.shutdownInput(); MyClient.shutdownOutput();
                input.close(); output.close(); MyClient.close();
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

    private static PublicKey getKeyFromCert(String other) throws NoSuchAlgorithmException {
        try (FileInputStream fis = new FileInputStream(other+".pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
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
            FileWriter file;
            imageName = imageName.substring(0, imageName.length()-4);
            if (folderName.endsWith("Sesh"))
                file = new FileWriter(folderName+"/Session Hash.txt");
            else file = new FileWriter(folderName+"/"+imageName+" Hash.txt");
            file.write(hexString.toString());
            file.close();
            return hexString.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void signHash(String folderName, String image) throws NoSuchAlgorithmException {
        Cipher cipher;
        String hash = hash(folderName,image);
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);
            byte[] signedHash = cipher.doFinal(hash.getBytes());
            FileOutputStream stream;
            if (folderName.endsWith("Sesh"))
                stream = new FileOutputStream(folderName+"/Session Hash.txt");
            else stream = new FileOutputStream(folderName+"/Image Hash.txt");
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

    private static void encrypt(File zipFile, IvParameterSpec iv) throws NoSuchAlgorithmException {
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

    private static void encrypt(String seshKeyFileName) throws NoSuchAlgorithmException {
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
            return "response: " + input.readUTF();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean handshake(String from, String to) throws NoSuchAlgorithmException {
        System.out.println("STARTING HANDSHAKE");
        //Send SYN + certificate
        String CHLO = "Asymmetric Encryption: RSA/ECB/PKCS1Padding\n" +
                "Symmetric Encryption: AES/CBC/PKCS5Padding\n" +
                "Hashing Algorithm: SHA256\n" +
                "Compression: Zip";
        try {
            output.writeUTF(CHLO);
            System.out.println(sendFile(from+".pem"));
            //Syn-Ack & certificate
            boolean synAck = input.readBoolean();
            if (!synAck) return false;
            String otherCert = input.readUTF();
            output.writeUTF(receiveFile(otherCert));
            otherPublicKey = getKeyFromCert(to);
            if (otherPublicKey == null) return false;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        File dir = new File(from+" Sesh");
        dir.mkdir();
        String plaintext = "Hi "+to+", it's "+from+".\n" +
                "I've sent you a session key ("+from+to+"Session.key) for us to use in future communications.\n" +
                "I look forward to hearing from you!";
        try {
            FileWriter file = new FileWriter(dir.getName()+"/Session.txt");
            file.write(plaintext);
            file.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        signHash(dir.getName(), "Session.txt");
        compressFiles(new String[]{dir.getName()+"/Session Hash.txt",dir.getName()+"/Session.txt"}, dir.getName()+".zip");
        File zip1stContact = new File(dir.getName()+".zip");
        sessionKey = generateSymKeys(from,to);

        if (iv == null) iv = generateIv();
        encrypt(zip1stContact, iv);
        encrypt(from+to+"Session.key");
        System.out.println(sendFile(from+to+"Session.key"));
        try {
            output.writeUTF(Base64.getEncoder().encodeToString(iv.getIV()));
            System.out.println(sendFile(dir.getName()+".zip"));
            return input.readBoolean();
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

    private static void decrypt(String encryptedSKname) throws NoSuchAlgorithmException {
        File encryptedSK= new File(encryptedSKname);
        byte[] skBytes = readAllBytes(encryptedSK);
        try {
            Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
            byte[] decryptedSK = decipher.doFinal(skBytes);
            FileOutputStream fos = new FileOutputStream(encryptedSK);
            fos.write(decryptedSK);
            fos.close();
            sessionKey = new SecretKeySpec(decryptedSK, "AES");
        } catch (BadPaddingException | NoSuchPaddingException e) {
            System.out.println("Incorrect Key!");
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void decrypt(String cipheredMessage, IvParameterSpec iv) throws NoSuchAlgorithmException {
        File encryptedZip = new File(cipheredMessage+".zip");
        byte[] skBytes = readAllBytes(encryptedZip);
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
        if (!outputDirectory.exists()) outputDirectory.mkdirs();
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
            new File(zipName+".zip").delete();
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
            FileWriter file;
            if (folderName.endsWith("Sesh"))
                file = new FileWriter(folderName+"/Hashed Session.txt");
            else file = new FileWriter(folderName+"/Hashed "+image.getName());
            file.write(hexString.toString());
            file.close();
            return hexString.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean compareHash(String folderName, String imageName) throws NoSuchAlgorithmException {
        File image = new File(folderName+"/"+imageName);
        String secondHash = hash2(folderName, image);
        String firstHash = "";
        try {
            Scanner hash1;
            imageName = imageName.substring(0, imageName.length()-4);
            if (folderName.endsWith("Sesh"))
                hash1 = new Scanner(new File(folderName+"/Session Hash.txt"));
            else hash1 = new Scanner(new File(folderName+"/"+imageName+" Hash.txt"));
            while (hash1.hasNext()) firstHash += hash1.nextLine();
            hash1.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        return secondHash.equals(firstHash);
    }

    private static boolean connect(String from, String to) throws NoSuchAlgorithmException {
        File otherCertFile = new File(to+".pem");
        boolean resumeSesh = true;
        if (otherCertFile.exists()) {
            if ((otherPublicKey = getKeyFromCert(to)) == null) {
                resumeSesh = false;
                otherCertFile.delete();
            }
            else {
                File seshKeyFile = new File(from+to+"Session.key");
                File seshKeyFileAlt = new File(to+from+"Session.key");
                if (seshKeyFile.exists()){
                    byte[] seshBytes = readAllBytes(seshKeyFile);
                    sessionKey = new SecretKeySpec(seshBytes, "AES");
                } else if (seshKeyFileAlt.exists()) {
                    byte[] seshBytes = readAllBytes(seshKeyFileAlt);
                    sessionKey = new SecretKeySpec(seshBytes, "AES");
                } else resumeSesh = false;
            }
        } else resumeSesh = false;
        try {
            output.writeUTF(from);
            if (!resumeSesh) {
                output.writeBoolean(true);
                resumeSesh = handshake(from, to);
                if (resumeSesh) System.out.println("Handshake Complete!");
            } else {
                output.writeBoolean(false);
                output.writeBoolean(resumeSesh);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return resumeSesh;
    }

    private static boolean shakeHands(String me, String other) throws NoSuchAlgorithmException {
        System.out.println("Handshake Initialised");
        String protocol = "Asymmetric Encryption: RSA/ECB/PKCS1Padding\n" +
                "Symmetric Encryption: AES/CBC/PKCS5Padding\n" +
                "Hashing Algorithm: SHA256\n" +
                "Compression: Zip";
        try {
            String syn = input.readUTF();
            String otherCert = input.readUTF();
            output.writeUTF(receiveFile(otherCert));
            otherPublicKey = getKeyFromCert(other);
            if (otherPublicKey == null || !syn.equalsIgnoreCase(protocol)) {
                output.writeBoolean(false); //SHLO
                return false;
            }
            output.writeBoolean(true); //syn-ack
            System.out.println(sendFile(me+".pem"));
            String seshKey = input.readUTF();
            output.writeUTF(receiveFile(seshKey));
            decrypt(seshKey);
            String initVec = input.readUTF();
            iv = new IvParameterSpec(Base64.getDecoder().decode(initVec));
            String sesh = input.readUTF(); //Zip
            output.writeUTF(receiveFile(sesh));
            sesh = sesh.substring(0, sesh.length()-4);
            decrypt(sesh, iv);
            decompressFiles(sesh);
            boolean auth = verifySender(sesh+"/Session Hash.txt", otherPublicKey);
            boolean integrity = compareHash(sesh, "Session.txt");
            if (!(auth && integrity)) {
                System.out.println("Authentication: " + auth);
                System.out.println("Integrity? " + integrity);
                return false;
            }
            output.writeBoolean(true);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println("Handshake Complete!");
        return true;
    }

    private static void connectedMenu() {
        Scanner consoleIn = new Scanner(System.in);
        try {
            while (!MyClient.isClosed()) {
                int request = 0; int resp = 0;
                if (input.available()>0)
                    request = input.readInt();
                else {
                    System.out.println("What do you want to do?\nEnter the corresponding number:\n" +
                            "1. Send Image\n" +
                            "2. Get Image\n" +
                            "3. End Session");
                    resp = consoleIn.nextInt();
                    consoleIn.nextLine();
                    if (resp == 1) {
                        output.writeInt(1);
                        File[] pics = new File("Images").listFiles();
                        for (File pic : pics)
                            System.out.println(pic.getName());
                        System.out.println("Type the name of the image you want to send including the extension (Case-Sensitive)");
                        String picName = consoleIn.nextLine();
                        hash("Images", picName);
                        String picNameH = picName.substring(0, picName.length()-4);
                        compressFiles(new String[]{"Images/"+picName, "Images/"+picNameH+" Hash.txt"}, "Images.zip");
                        encrypt(new File("Images.zip"), iv);
                        System.out.println(sendFile("Images.zip"));
                        output.writeUTF(picName);
                    } else if(resp == 2) {
                        output.writeInt(2);
                        System.out.println(input.readUTF());
                        String image = consoleIn.nextLine();
                        output.writeUTF(image);
                        String picName = input.readUTF();
                        output.writeUTF(receiveFile(picName));
                        decrypt("Images", iv);
                        decompressFiles("Images");
                        if (!compareHash("Images", image)) {
                            System.out.println("Integrity compromised: Message has been altered. Ending session");
                            break;
                        }
                    } else if (resp == 3) break;
                    Thread.sleep(8000);
                }

                if (request == 1) {
                    String imageName = input.readUTF();
                    output.writeUTF(receiveFile(imageName));
                    decrypt("Images", iv);
                    decompressFiles("Images");
                    imageName = input.readUTF();
                    if (!compareHash("Images", imageName)) {
                        System.out.println("Integrity compromised: Message has been altered. Ending session");
                        break;
                    }
                } else if (request == 2) {
                    String picsMenu = "";
                    File[] pics = new File("Images").listFiles();
                    for (File pic : pics)
                        picsMenu += pic.getName()+"\n";
                    picsMenu += "Type the name of the image you want including the extension (Case-Sensitive)";
                    output.writeUTF(picsMenu);
                    String picName = input.readUTF();
                    hash("Images", picName);
                    String picNameH = picName.substring(0, picName.length()-4);
                    compressFiles(new String[]{"Images/"+picName, "Images/"+picNameH+" Hash.txt"}, "Images.zip");
                    encrypt(new File("Images.zip"), iv);
                    System.out.println(sendFile("Images.zip"));
                } else if (request == 3) break;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        FilenameFilter nameFilter = (dir, name) -> name.endsWith(".pub");
        File[] pubKeyFile = new File(".").listFiles(nameFilter);

        Scanner consoleIn = new Scanner(System.in);
        boolean running = true;
        if (pubKeyFile.length != 0) {
            myName = pubKeyFile[0].getName();
            myName = myName.substring(0, myName.length()-4);
            System.out.println("Welcome Back "+myName+"!");
        }
        else {
            System.out.println("What's your name?");
            myName = consoleIn.nextLine().strip();
        }
        if (myPrivateKey == null || myPublicKey == null) getKeys(myName);
        System.out.println();
        do {
            System.out.println("What do you want to do?\nEnter the corresponding number:\n" +
                    "1. Contact Someone\n" +
                    "2. Wait (1 min) to be Contacted\n" +
                    "3. Quit");
            int response = consoleIn.nextInt();
            consoleIn.nextLine();
            switch (response) {
                case 1: {
                    System.out.println("Who do you want to contact?");
                    String otherName = consoleIn.nextLine().strip();
                    try {
                        MyClient = new Socket("localhost", 8200);
                        input = new DataInputStream(MyClient.getInputStream());
                        output = new DataOutputStream(MyClient.getOutputStream());

                        System.out.println();
                        if (connect(myName, otherName)) {
                            System.out.println();
                            output.writeUTF("Connected to "+otherName);
                            System.out.println(otherName+" response: "+input.readUTF());

                            ////////
                            if (iv == null) {
                                iv = generateIv();
                                String ivAsString = Base64.getEncoder().encodeToString(iv.getIV());
                                output.writeUTF(ivAsString);
                            }
                            connectedMenu();
                            /////////

                            System.out.println(otherName+" response: "+input.readUTF());
                            output.writeUTF("Disconnecting");
                            System.out.println();
                        } else System.out.println("Handshake Failed!");

                        iv = null;
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
                    ///Send or request
                    break;
                }
                case 2: {
                    try {
                        System.out.println("waiting...");
                        ServerSocket MyService = new ServerSocket(8200);
                        MyService.setSoTimeout(45*1000);
                        MyClient = MyService.accept();
                        input = new DataInputStream(MyClient.getInputStream());
                        output = new DataOutputStream(MyClient.getOutputStream());

                        String otherName = input.readUTF();
                        boolean handshake = input.readBoolean();
                        boolean connected;
                        if (handshake)
                            connected = shakeHands(myName, otherName);
                        else {
                            File seshKeyFile = new File(myName+otherName+"Session.key");
                            File seshKeyFileAlt = new File(otherName+myName+"Session.key");
                            if (seshKeyFile.exists()){
                                byte[] seshBytes = readAllBytes(seshKeyFile);
                                sessionKey = new SecretKeySpec(seshBytes, "AES");
                            } else if (seshKeyFileAlt.exists()) {
                                byte[] seshBytes = readAllBytes(seshKeyFileAlt);
                                sessionKey = new SecretKeySpec(seshBytes, "AES");
                            }
                            connected = input.readBoolean();
                        }

                        if (connected) {
                            System.out.println();
                            System.out.println(otherName+" response: "+input.readUTF());
                            output.writeUTF("Connected to "+ otherName);

                            if (iv == null) {
                                String ivAsString = input.readUTF();
                                iv = new IvParameterSpec(Base64.getDecoder().decode(ivAsString));
                            }
                            System.out.println("processing...");
                            Thread.sleep(8000);
                            connectedMenu();

                            output.writeUTF("Disconnecting");
                            System.out.println(otherName+" response: "+input.readUTF());
                            System.out.println();
                        } else System.out.println("Handshake Failed!");

//                        while (!MyClient.isClosed()){
//                            String request = input.readUTF();
//                        }
                        iv = null;
                        input.close();
                        output.close();
                        MyClient.close();
                        MyService.close();
                    } catch (SocketException e) {
                        throw new RuntimeException(e);
                    } catch (SocketTimeoutException e){
                        System.out.println("Sender took far too long");
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                    break;
                }
                case 3:
                {
                    FilenameFilter seshKeyFilter = (dir, name) -> name.endsWith(".key");
                    File[] seshKeys = new File(".").listFiles(seshKeyFilter);
                    for (File seshKey : seshKeys)
                        seshKey.delete();
                    running = false;
                }
            }
        } while (running);
    }
}
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


public class ClientHandler implements Runnable {

    private CertificateAuthority certAuth;
    private  Socket clientService;
    private  DataInputStream input;
    private  DataOutputStream output;


    public ClientHandler(Socket clientService, DataInputStream in, DataOutputStream out, CertificateAuthority ca) {
        this.input = in;
        this.clientService = clientService;
        this.output = out;
        this.certAuth = ca;
        try {
            System.out.println(input.readUTF());
            output.writeUTF("Connected");
        } catch (IOException e) {
            throw new RuntimeException(e);
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

    private String sendFile(String fileName) {
        System.out.printf("Sending file %s\n", fileName);
        File file = new File(fileName);
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            int bytesRead = 0;
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
            return "client response: " + input.readUTF();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void run() {
        try {
            while (!clientService.isClosed()){
                String request = "";
                if (input.available()>0)
                    request = input.readUTF();
                if (request.equals("Certificate Signing Request")){
                    System.out.println(sendFile("CA.pem"));
                    String client = input.readUTF();
                    System.out.println(client+"'s Certificate Signing Request");
                    byte[] digitalSignature = new byte[256];
                    input.read(digitalSignature);
                    byte[] clientKeyBytes = new byte[2048];
                    input.read(clientKeyBytes);
                    EncodedKeySpec myPubKeySpec = new X509EncodedKeySpec(clientKeyBytes);
                    PublicKey clientKey = KeyFactory.getInstance("RSA").generatePublic(myPubKeySpec);
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initVerify(clientKey);
                    signature.update(client.getBytes());
                    if (signature.verify(digitalSignature)) {
                        certAuth.generateCert(client, clientKey);
                        output.writeBoolean(true);
                        System.out.println(sendFile(client+".pem"));
                    }
                    else output.writeBoolean(false);
                }
                else if (request.equals("Requesting Certificate")){
                    String person1 = input.readUTF();
                    String person2 = input.readUTF();
                    System.out.println(person1+" Requesting "+person2+"'s Certificate");
                    if (certAuth.exists(person2)) {
                        output.writeBoolean(true);
                        System.out.println(sendFile(person2+".pem"));
                    } else {
                        output.writeBoolean(false);
                        System.out.println("Certificate doesn't exist!");
                        String[] people = certAuth.certList();
                        output.writeInt(people.length);
                        for (String person : people) output.writeUTF(person);
                        //output.write();
                    }
                } else if (request.equals("Disconnected")) {
                    clientService.close();
                }
            }
            System.out.println("Client Disconnected");
            output.close();
            input.close();
            clientService.close();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

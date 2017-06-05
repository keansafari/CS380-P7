/**
 *
 * @author Khjafari
 */

import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import static java.lang.System.in;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.net.*;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.WRAP_MODE;
import static javax.crypto.Cipher.getInstance;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class FileTransfer {
    
    private static SecretKey secretKey;
    
    public static void main(String[] args) throws IOException, Exception {
        String command = args[0];
        if (command.equals("makekeys")) 
            makekeys();
        if (command.equals("server")) 
            server(args);
        if (command.equals("client")) 
            client(args);
    }
    
    
    public static void makekeys() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(4096);
            KeyPair keypair = gen.genKeyPair();
            PrivateKey privatekey = keypair.getPrivate();
            PublicKey publickey = keypair.getPublic();
            try (ObjectOutputStream oos = new ObjectOutputStream (new FileOutputStream(new File("public.bin")))) {
                oos.writeObject(publickey);
            } catch (Exception e) {}
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) {
                oos.writeObject(privatekey);
            } catch (Exception e) {}
        } catch (NoSuchAlgorithmException e) {}
    }
    
    public static void server(String[] cmd) throws IOException, Exception {
        String privateKeyName = cmd[1];
        int port = Integer.parseInt(cmd[2]);
        System.out.println("Launcing in server mode...");
        try(ServerSocket serverSocket = new ServerSocket(port)) {
            Socket socket = serverSocket.accept();
            String address = socket.getInetAddress().getHostAddress();
            System.out.printf("Client connected: %s%n", address);
            InputStream is = socket.getInputStream();
            ObjectInputStream ois = new ObjectInputStream(is);
            OutputStream os = socket.getOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(os);
            //Loop to keep server on -- Stays open for multiple connections
            while (true) {
                try {
                    //Expects a StartMessage for now!
                    StartMessage sm = (StartMessage) ois.readObject();
                    //Respond with an AckMessage
                    AckMessage am = new AckMessage(0);
                    oos.writeObject(am);
                    //DECRYPTING ENCRYPTED KEY
                    System.out.println("Decrypting the session key...");
                    Cipher cipher = getInstance("RSA");
                    ObjectInputStream importPrivateKey = new ObjectInputStream(new FileInputStream(privateKeyName));
                    RSAPrivateKey rsa = (RSAPrivateKey) importPrivateKey.readObject();
                    cipher.init(Cipher.UNWRAP_MODE, rsa);
                    secretKey = (SecretKey)cipher.unwrap(sm.getEncryptedKey(), "AES", Cipher.SECRET_KEY);
                    System.out.println("Session Key successfully decrpyted.");

                    //Calculations for chunksize and num of chunks
                    int chunkSize = (int)sm.getChunkSize();
                    int fileSize = (int)sm.getSize();
                    int numOfChunks = (int)(Math.ceil((double)fileSize / (double)chunkSize));

                    /*Receiving Chunks
                    // 1) Receieve Object
                    // 2) decrypt message
                    // 3) get crc and compare with Chunk to check if message is same
                    // 4) write decrypted message on a text file 
                    **/
                    String finalMessage = "";
                    byte[] decryptedChunk;
                    for(int i = 0; i < numOfChunks; i++) {
                        Chunk c = (Chunk)ois.readObject();
                        System.out.println("Chunk[" + c.getSeq() + "/" + numOfChunks + "]\treceived.");
                        decryptedChunk = decryptChunk(c.getData(), secretKey);
                        int checksum = getChecksum(decryptedChunk);
                        if (checksum == c.getCrc()) {
                            finalMessage += new String(decryptedChunk);
                            AckMessage ack = new AckMessage((c.getSeq() + 1));
                            oos.writeObject(ack);
                        }
                        else {
                           System.out.println("ERROR WITH FILE TRANSFER\nCLOSING PROGRAM.");
                           System.exit(0);
                        } 
                    }
                    
                    writeToFile(finalMessage);
                    checkEnd(socket);
                    ois.close();
                    os.close();
                    is.close();
                    ois.close();
                    
                }catch (Exception e) {}
            }
        }
    }
    
    public static void client(String[] cmd) throws Exception {
        String publicKey = cmd[1];
        String host = cmd[2];
        int port = Integer.parseInt(cmd[3]);
        
        //Creates the session key
        byte[] sessionKey = createSessionKey(publicKey);
        
        try (Socket socket = new Socket(host, port)) {
            if (socket.isConnected()) {
                Scanner kb = new Scanner(System.in);
                System.out.println("Successfully connected.");
                
                while (true){
                    //Gets file name to write to from user 
                    System.out.print("Enter Output File: ");
                    String outputFileName = kb.nextLine();
                    if (outputFileName.equals("!q")) {
                        StopMessage stop = new StopMessage(outputFileName);
                        OutputStream os = socket.getOutputStream();
                        ObjectOutputStream oos = new ObjectOutputStream(os);
                        oos.writeObject(stop);
                        System.exit(0);
                    }
                    //Opens file + gets size
                    File outputFile = new File(outputFileName);
                    long fileSize = 0;
                    int numOfChunks = 0;
                    int chunkSize = 0;
                    if(outputFile.exists()) {
                        fileSize = outputFile.length();
                        //Gets chunk size from user

                        System.out.print("Enter chunk size[default:1024]: ");
                        String chunkStr = kb.nextLine();

                        if (chunkStr.length() == 0) 
                            chunkSize = 1024;
                        else
                            chunkSize = Integer.parseInt(chunkStr);
                        //Makes numOfChunks so it rounds UP every time -- remainder is sent in last chunk
                        numOfChunks = (int) Math.ceil(((double)fileSize / (double)chunkSize));



                    }

                    System.out.println("Sending: " + outputFileName + "\tFile Size: "
                            + fileSize + "bytes in " + numOfChunks + " chunks.");

                    //Sends the file in chunks
                    sendFile(outputFile, numOfChunks, socket, chunkSize, sessionKey);
                    System.out.println("Enter '!q' to quit");
                }
            }
            
        }
    }
    
    public static void sendFile(File outputFile, int numOfChunks, Socket socket, int chunkSize, byte[] sessionKey) throws Exception {
        System.out.println("Starting transfer process...");
        StartMessage messageInfo = new StartMessage(outputFile.getName(), sessionKey, chunkSize);
        
        
        OutputStream os = socket.getOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(os);
        //Sends the START_MESSAGE to the server
        oos.writeObject(messageInfo);
        System.out.println("Acknowledgement sent...");

        InputStream is = socket.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(is);            

        //Writes ack message
        AckMessage am = (AckMessage)ois.readObject();
        if (am.getSeq() == 0)
            System.out.println("Acknowledgement: Success\nSending File...");
        if (am.getSeq() == -1)
            System.out.println("Acknowledgement: Failed");
        //Send chunks
        byte[] readAllByte = Files.readAllBytes(outputFile.toPath());       //Reads File to byte array
        //printByteData(readAllByte);
        byte[] normalChunks = new byte[chunkSize];                          //Normal Chunk
        byte[] lastChunk = new byte[(int)outputFile.length() % chunkSize];  //last chunk (remainder)
        byte[] encryptedChunk = null;
        int byteCounter = 0;
        
        //Sends n Number of Chunks
        //in for loop -- 
        // 1.) big byte array to small byte array
        // 2.) get crc of small byte array
        // 3.) encrypt small byte array
        // 4.) package into chunk and send to server
        int checksum = 0;
        Chunk c;
        for (int i = 1; i <= numOfChunks; i++) {
            int sequence = i;
            
            if (i == numOfChunks && lastChunk.length > 0) {
                for (int k = 0; k < ((int)outputFile.length() % chunkSize); k++) {
                    lastChunk[k] = readAllByte[byteCounter];
                    byteCounter++;
                }
                checksum = getChecksum(lastChunk);
                encryptedChunk = encryptChunk(lastChunk);
            }
            else {
                for (int j = 0; j < chunkSize; j++) {
                    normalChunks[j] = readAllByte[byteCounter];
                    byteCounter++;
                }
                checksum = getChecksum(normalChunks);
                encryptedChunk = encryptChunk(normalChunks);
            }
            c = new Chunk(sequence, encryptedChunk, checksum);
            oos.writeObject(c);
            System.out.println("Chunk[" + c.getSeq() + "/" + numOfChunks + "]\tsent.");
            
            //Receive Ack
           AckMessage ack = (AckMessage)ois.readObject();
           
        }
    }
            
 
    public static void checkEnd(Socket socket) {
        try {
            InputStream is = socket.getInputStream();
            ObjectInputStream ois = new ObjectInputStream(is);
            StopMessage stop = new StopMessage("test.txt");
            System.exit(0);
        } catch (Exception e) {}
    }
    public static void printByteData(byte[] data) {
        String str = new String(data);
        System.out.println(str);
    }
    
    public static byte[] encryptChunk(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedChunk = cipher.doFinal(data);
        return encryptedChunk;
    }
    
    public static byte[] decryptChunk(byte[] data, Key key) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedChunk = c.doFinal(data);
        return decryptedChunk;
    }
    //CREATE AES SESSION KEY
    public static byte[] createSessionKey(String publicKeyName) throws Exception {
        //Creates an AES session key at 128bit strength
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(publicKeyName));
        RSAPublicKey publicKey = (RSAPublicKey) ois.readObject();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        secretKey = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.WRAP_MODE, publicKey);
        byte[] sKey = cipher.wrap(secretKey);
        return sKey;
       
        
        
    }
    
    public static int getChecksum(byte[] packet) {
        //Calculates the checksum
        int length = packet.length;
        int i = 0;
        long total = 0;
        int sum = 0;

        // add to sum and bit shift
        while (length > 1) {
        sum = sum + ((packet[i] << 8 & 0xFF00) | ((packet[i+1]) & 0x00FF));
        i = i + 2;
        length = length - 2;

        // splits byte into 2 words, adds them.
        if ((sum & 0xFFFF0000) > 0) {
            sum = sum & 0xFFFF;
            sum++;
        }
    }

        // calculates and adds overflowed bits, if any
        if (length > 0) {
        sum += packet[i] << 8 & 0xFF00;
            if ((sum & 0xFFFF0000) > 0) {
                    sum = sum & 0xFFFF;
                    sum++;
            }
        }
        return sum;
    }
    
    public static void writeToFile(String msg) throws IOException {
        
        BufferedWriter out = new BufferedWriter(new FileWriter("output.txt"));
        out.write(msg);
        out.close();
        
    }
    
}

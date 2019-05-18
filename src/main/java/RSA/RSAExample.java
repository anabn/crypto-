package RSA;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RSAExample {

    public static final String ALGORITHM = "RSA";
    public static final String PUBLIC_KEY_FILE = "Public";
    public static final String PRIVATE_KEY_FILE = "Private";
    public static final int random = 2048;
    public static String message = "\n I wake up everyday planning to be productive " +
            "and \n then a voice in my head says \"haha good one\" " +
            "\n and we laugh and laugh and take a nap.\n" ;

//    public static boolean areKeysPresent() {
////
////        File privateKey = new File(PRIVATE_KEY_FILE);
////        File publicKey = new File(PUBLIC_KEY_FILE);
////
////        if (privateKey.exists() && publicKey.exists()) {
////            return true;
////        }
////        return false;
////    }

    public void saveKeys(String fileName, BigInteger mod, BigInteger exp) throws IOException{
        FileOutputStream fileOutputStream = null;
        ObjectOutputStream objectOutputStream = null;
        try{
            System.out.println("Generating [" + fileName + "] key...");
            fileOutputStream = new FileOutputStream(fileName);
            objectOutputStream = new ObjectOutputStream(new BufferedOutputStream(fileOutputStream));
            objectOutputStream.writeObject(mod);
            objectOutputStream.writeObject(exp);
            System.out.println("["+fileName + "] key generated successfully\n");
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            if (objectOutputStream != null) {
                objectOutputStream.close();
                if (fileOutputStream != null) {
                    fileOutputStream.close();
                }
            }
        }
    }

    public PublicKey readPublicKeyFromFile (String fileName) throws IOException{
        FileInputStream fileInputStream = null;
        ObjectInputStream objectInputStream = null;
        try {
            fileInputStream = new FileInputStream(new File(fileName));
            objectInputStream = new ObjectInputStream(fileInputStream);
            BigInteger modulus = (BigInteger) objectInputStream.readObject();
            BigInteger exponent =  (BigInteger) objectInputStream.readObject();

            //Get Public Key
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            PublicKey publicKey = factory.generatePublic(rsaPublicKeySpec);
            return publicKey;
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
            if (objectInputStream != null) {
                objectInputStream.close();
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            }
        }
        return null;
    }

    public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException {
        FileInputStream fileInputStream = null;
        ObjectInputStream objectInputStream = null;
        try{
            fileInputStream = new FileInputStream(new File(fileName));
            objectInputStream = new ObjectInputStream(fileInputStream);
            BigInteger modulus = (BigInteger) objectInputStream.readObject();
            BigInteger exponent =  (BigInteger) objectInputStream.readObject();

            //Get Private Key
            RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            PrivateKey privateKey = factory.generatePrivate(rsaPrivateKeySpec);
            return privateKey;
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
            if (objectInputStream != null) {
                objectInputStream.close();
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            }
        }
        return null;
    }

    // Encryption & decryption using Public key
    public byte[] encryptData(String data) throws IOException {
        System.out.println("\t [Encryption for Public started ] \n");
        System.out.println("[Data before Encryption]:" + data);
        byte[] dataToEncrypt = data.getBytes();
        byte[] encryptedData = null;
        try {
            PublicKey publicKey = readPublicKeyFromFile(this.PUBLIC_KEY_FILE);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedData = cipher.doFinal(dataToEncrypt);
//            System.out.println("Encryption data: " + new String(encryptedData, "UTF-8"));
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        System.out.println("\t [Encryption for Public completed]\n");
        return encryptedData;
    }

    public void decryptData(byte[] data) throws IOException {
        System.out.println("\t [Decrypting for Public started]\n");
        byte[] decryptedData = null;
        try{
            PrivateKey privateKey = readPrivateKeyFromFile(this.PRIVATE_KEY_FILE);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedData = cipher.doFinal(data);
            System.out.println("[Decrypted  Data]: " + new String(decryptedData));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        System.out.println("\t  [Decrypting for Public completed]\n");
    }

    // Encryption & decryption using Private key
    public byte[] encryptDataForPrivate(String data) throws IOException {
        System.out.println("\t [Encryption for Private started]\n");
        System.out.println("[Data before Encryption]:" + data);
        byte[] dataToEncrypt = data.getBytes();
        byte[] encryptedData = null;
        try {
            PrivateKey privateKey = readPrivateKeyFromFile(this.PRIVATE_KEY_FILE);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            encryptedData = cipher.doFinal(dataToEncrypt);
//            System.out.println("Encryption data: " + new String(encryptedData, "UTF-8"));
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        System.out.println("\t [Encryption for Private completed]\n");
        return encryptedData;
    }

    public void decryptDataForPrivate(byte[] data) throws IOException {
        System.out.println("\t [Decrypting for Private started]\n");
        byte[] descreptedData = null;
        try{
            PublicKey publicKey = readPublicKeyFromFile(this.PUBLIC_KEY_FILE);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            descreptedData = cipher.doFinal(data);
            System.out.println("[Decrypted Data]: " + new String(descreptedData));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        System.out.println("\t  [Decrypting for Private completed]\n");
    }

}

package RSA;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class Main {

    public static void main(String[] args) throws IOException {
        RSAExample rsaObj = new RSAExample();
        try {
            System.out.println("\t Generate public and private key\n");
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSAExample.ALGORITHM);
            keyPairGenerator.initialize(RSAExample.random, new SecureRandom());
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println("\t pulling our parameters which makes keypair\n");

            KeyFactory keyFactory = KeyFactory.getInstance(RSAExample.ALGORITHM);
            RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);

            System.out.println("\t saving public & private key to files\n");

            rsaObj.saveKeys(RSAExample.PUBLIC_KEY_FILE, rsaPublicKeySpec.getModulus(), rsaPublicKeySpec.getPublicExponent());
            rsaObj.saveKeys(RSAExample.PRIVATE_KEY_FILE, rsaPrivateKeySpec.getModulus(), rsaPrivateKeySpec.getPrivateExponent());

            //Encrypt data using Public Key
            byte[] encryptedData = rsaObj.encryptData(RSAExample.message);
            rsaObj.decryptData(encryptedData);

            //Encrypt data using Private Key
            byte[] encryptedDataForPrivate = rsaObj.encryptDataForPrivate(RSAExample.message);
            rsaObj.decryptDataForPrivate(encryptedDataForPrivate);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

}

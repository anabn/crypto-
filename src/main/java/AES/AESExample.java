package AES;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;


public class AESExample {

    private static final String ALGORITHM = "AES";
    private static int size = 256;
    private static int maxKeyLen = 0;
    public static String message = " I wake up everyday planning to be productive " +
            "and \n then a voice in my head says \"haha good one\" " +
            "\n and we laugh and laugh and take a nap.\n" ;

    public String enctypt (String Data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // получить/создать симметричный ключ шифрования
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = cipher.doFinal(Data.getBytes());
        String mimeEncodedString = Base64.getMimeEncoder().encodeToString(encVal);
        return mimeEncodedString;
    }

    public String decrypt (String encryptedData, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = Base64.getMimeDecoder().decode(encryptedData);
        byte[] decValue = cipher.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }

    public static void main(String[] args) {
        AESExample aes = new AESExample();

        try{
            final KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(size); // 256
            final SecretKey key = keyGen.generateKey();

            String encdata = aes.enctypt(message, key);
            String decdata = aes.decrypt(encdata, key);
            System.out.println("\t [Encrypted Data]: \n" + encdata + "\n");
            System.out.println("\t [Decrypted Data]: \n" + decdata);

            maxKeyLen = Cipher.getMaxAllowedKeyLength(ALGORITHM);
        System.out.println("MaxAllowedKeyLength=[" + maxKeyLen + "].");
        } catch (Exception e) {
            Logger.getLogger(AESExample.class.getName()).log(Level.SEVERE, null, e);
        }
    }
}

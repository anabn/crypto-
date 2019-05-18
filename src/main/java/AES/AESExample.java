package AES;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AESExample {

    private static final String ALGORITHM = "AES";
    private static final String key = "azwsqazxswedcvfr"; // 16 bytes / 128 bit - key size
    private byte[] keyValue;
    public static String message = " I wake up everyday planning to be productive " +
            "and \n then a voice in my head says \"haha good one\" " +
            "\n and we laugh and laugh and take a nap.\n" ;

    public AESExample (String key) {
        keyValue = key.getBytes();
    }
    private Key generateKey() throws Exception {
        Key key = new SecretKeySpec(keyValue, ALGORITHM);
        return key;
    }

    public String enctypt (String Data) throws Exception {
        Key key = generateKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // получить/создать симметричный ключ шифрования
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = cipher.doFinal(Data.getBytes());
        String encryptedValue = new BASE64Encoder().encode(encVal);
        return encryptedValue;
    }

    public String decrypt (String encryptedData) throws Exception {
        Key key = generateKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
        byte[] decValue = cipher.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }

    public static void main(String[] args) {

        try{
            AESExample aes = new AESExample( key);
            String encdata = aes.enctypt(message);
            System.out.println("\t [Encrypted Data]: \n" + encdata + "\n");
            String decdata = aes.decrypt(encdata);
            System.out.println("\t [Decrypted Data]: \n" + decdata);

            int maxKeyLen = Cipher.getMaxAllowedKeyLength(ALGORITHM);
            System.out.println("MaxAllowedKeyLength=[" + maxKeyLen + "].");

        } catch (Exception e) {
//            Logger.getLogger(AESExample.class.getName()).log(Level.SEVERE, null, e);
            e.printStackTrace();
        }
    }
}

package Basictask;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

public class PasswordManager {
	private static SecretKey secretKey;

	public static void main(String[] args) {
		 try {
	            
	            secretKey = generateSecretKey();

	           
	            String generatedPassword = generatePassword();
	            System.out.println("Generated password: " + generatedPassword);

	            
	            String encryptedPassword = encryptPassword(generatedPassword);
	            System.out.println("Encrypted password: " + encryptedPassword);

	            
	            String decryptedPassword = decryptPassword(encryptedPassword);
	            System.out.println("Decrypted password: " + decryptedPassword);
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }

	    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
	        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	        keyGenerator.init(128); 
	        return keyGenerator.generateKey();
	    }

	    private static String generatePassword() {
	        
	        Scanner scanner = new Scanner(System.in);
	        System.out.print("Enter your password: ");
	        return scanner.nextLine();
	    }

	    private static String encryptPassword(String password) throws Exception {
	        Cipher cipher = Cipher.getInstance("AES");
	        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
	        return Base64.getEncoder().encodeToString(encryptedBytes);
	    }

	    private static String decryptPassword(String encryptedPassword) throws Exception {
	        Cipher cipher = Cipher.getInstance("AES");
	        cipher.init(Cipher.DECRYPT_MODE, secretKey);
	        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
	        return new String(decryptedBytes);
	    }
	}

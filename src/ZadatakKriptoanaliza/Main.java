package ZadatakKriptoanaliza;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class Main {

	public static void main(String[] args) {
		byte[] encryptedBytes = encryptAES("Hristina Milkic", generateKeyBytes(12345));
		String ciphertextHex = bytesToHex(encryptedBytes);

	    byte[] ciphertext = hexStringToByteArray(ciphertextHex);

	    int startKey = 0x000000; 
	    int endKey = 0x00FFFF;  

	    String bestPlaintext = "";
	    double lowestEntropy = Double.MAX_VALUE;

	    for (int key = startKey; key <= endKey; key++) {
	        byte[] keyBytes = generateKeyBytes(key);
	        String decryptedText = decryptAES(ciphertext, keyBytes);

	        if (decryptedText != null) {
	            System.out.println("Pokušaj sa ključem " + key + " -> " + decryptedText);
	            double entropy = calculateEntropy(decryptedText);
	            if (entropy < lowestEntropy) {
	                lowestEntropy = entropy;
	                bestPlaintext = decryptedText;
	            }
	        }
	    }

	    System.out.println("Najbolji match (Najmanja entropija): " + bestPlaintext);
	}
	
	private static byte[] encryptAES(String plaintext, byte[] keyBytes) {
	    try {
	        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
	        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
	        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	        byte[] plaintextBytes = Arrays.copyOf(plaintext.getBytes(StandardCharsets.UTF_8), 16);
	        return cipher.doFinal(plaintextBytes);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}


	private static byte[] generateKeyBytes(int key) {
	    byte[] keyBytes = new byte[16];
	    for (int i = 0; i < 4; i++) {
	        keyBytes[i] = (byte) ((key >> (8 * i)) & 0xFF);
	    }
	    Arrays.fill(keyBytes, 4, 16, (byte) 0);
	    return keyBytes;
	}


    private static String decryptAES(byte[] ciphertext, byte[] keyBytes) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] plaintextBytes = cipher.doFinal(ciphertext);
            return new String(plaintextBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null; 
        }
    }

    private static double calculateEntropy(String text) {
        Map<Character, Integer> frequency = new HashMap<>();
        for (char c : text.toCharArray()) {
            frequency.put(c, frequency.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        int length = text.length();
        for (int count : frequency.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }


    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}

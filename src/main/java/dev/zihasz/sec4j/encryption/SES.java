package dev.zihasz.sec4j.encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Java implementation of SES (secure encryption standard), a wrapper around AES and SHA512.
 * @author zihasz
 */
public class SES {

	/**
	 * A more secure version of AES-256. Encryption part.
	 * @param text The string to encrypt.
	 * @param key The key to use for encrypting the text.
	 * @param salt1 The first salt. Used as the 'string' parameter for the secureHash function.
	 * @param salt2 The second salt. Used as the 'salt' parameter for the secureHash function.
	 * @return The encrypted value as a hexadecimal string.
	 */
	public static String encrypt( String text, String key, String salt1, String salt2) {
		String encrypted = AES.encrypt(text, key, hash(salt1, salt2));
		if (encrypted == null) throw new IllegalStateException("Encrypted AES value null!");
		return stringToHex(Base64.getEncoder().encodeToString(encrypted.getBytes()));
	}

	/**
	 * A more secure version of AES-256. Decryption part.
	 * @param text The encrypted text to decrypt.
	 * @param key The key used the encrypt the original text.
	 * @param salt1 The first salt. Used as the 'string' parameter for the secureHash function.
	 * @param salt2 The second salt. Used as the 'salt' parameter for the secureHash function.
	 * @return The decrypted value as a string.
	 */
	public static String decrypt( String text, String key, String salt1, String salt2) {
		String decrypted = AES.decrypt(new String(Base64.getDecoder().decode(hexToString(text))), key, hash(salt1, salt2));
		if (decrypted == null) throw new IllegalStateException("Decrypted AES value null!");
		return decrypted;
	}

	/**
	 * A SHA-512 salted version of SHA-512.
	 * @param string The text to hash.
	 * @param salt The salt to use for hashing.
	 * @return The hashed value as a string.
	 */
	public static String hash(String string, String salt) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			char[] charArray = string.toCharArray();
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < string.length(); i++) {
				sb.append(charArray[i]).append(new String(md.digest(salt.getBytes())));
			}
			return new String(md.digest(sb.toString().getBytes()));
		} catch (NoSuchAlgorithmException ignored) {
			return "";
		}
	}

	/**
	 * Convert hexadecimal strings to strings.
	 * @param hex The hexadecimal string to convert into a string.
	 * @return Returns the string value.
	 */
	public static String hexToString(String hex) {
		StringBuilder sb = new StringBuilder();
		char[] charArray = hex.toCharArray();
		for (int i = 0; i < charArray.length; i += 2) {
			sb.append((char) Integer.parseInt(String.valueOf(charArray[i]) + charArray[i + 1], 16));
		}
		return sb.toString();
	}

	/**
	 * Convert strings to hexadecimal strings.
	 * @param string The string value to convert into a hexadecimal string.
	 * @return Returns the hexadecimal string value.
	 */
	public static String stringToHex(String string) {
		StringBuilder sb = new StringBuilder();
		char[] charArray = string.toCharArray();
		for (char character : charArray) {
			sb.append(Integer.toHexString(character));
		}
		return sb.toString();
	}

}

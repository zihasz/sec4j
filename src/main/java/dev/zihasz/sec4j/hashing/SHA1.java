package dev.zihasz.sec4j.hashing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA1 {

	public static byte[] sha1(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		return md.digest(data);
	}
	public static String sha1(String data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		return new String(md.digest(data.getBytes()));
	}

}

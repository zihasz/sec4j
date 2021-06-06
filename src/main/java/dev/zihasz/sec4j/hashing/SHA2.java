package dev.zihasz.sec4j.hashing;

import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA2 {

	public static byte[] sha224(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-224");
		return md.digest(data);
	}
	public static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA256");
		return md.digest(data);
	}
	public static byte[] sha384(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		return md.digest(data);
	}
	public static byte[] sha512(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		return md.digest(data);
	}
	public static byte[] sha512_224(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-512/224");
		return md.digest(data);
	}
	public static byte[] sha512_256(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-512/256");
		return md.digest(data);
	}

	public static String sha224(@NotNull String data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-224");
		return new String(md.digest(data.getBytes()));
	}
	public static String sha256(@NotNull String data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return new String(md.digest(data.getBytes()));
	}
	public static String sha384(@NotNull String data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		return new String(md.digest(data.getBytes()));
	}
	public static String sha512(@NotNull String data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		return new String(md.digest(data.getBytes()));
	}
	public static String sha512_224(@NotNull String data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-512/224");
		return new String(md.digest(data.getBytes()));
	}
	public static String sha512_256(@NotNull String data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-512/256");
		return new String(md.digest(data.getBytes()));
	}
	
}

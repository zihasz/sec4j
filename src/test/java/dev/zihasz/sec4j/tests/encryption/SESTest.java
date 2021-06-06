package dev.zihasz.sec4j.tests.encryption;

import dev.zihasz.sec4j.encryption.SES;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SESTest {

	@Test
	public void testSESEncryptDecrypt() {

		String key = "MyKey";
		String slt1 = "MySlt1";
		String slt2 = "MySlt2";

		String input = "SES Test 1";
		String encrypted = SES.encrypt(input, key, slt1, slt2);
		String decrypted = SES.decrypt(encrypted, key, slt1, slt2);

		assertEquals(input, decrypted, "Decrypted should be equal with input");
	}

	@Test
	public void testSESEncryptDecrypt2() {

		String key = "CIE512IV8G4SEURfcnsyMAzC6HO7q8vKrtvDwajmvj6jHAjsWarvryQSgosYj6OuIJoYdSKdVBBuwv5t0q0067qvbwnjIk4R4gXcSeRd9awbl97ET3SEKmPPPUY1O7vrSMIdOuvbom1lJsljZImlGdODWABhrOOm5kYI2xvqF81RosVhZNe70feRQCONqxERhaiHQo8ikGGt7El1skKgYzSNQjViijyDpDouoHqVxEBAwQfSodRBBaDcDhwAAFdH";
		String slt1 = "Q4dB10tAxeAGUfFefAuAcOOFMgM6cyh33Yawmn4bABYYJErle6fR3DyF5DLwA7bPgx5kP3tlNePcybHybA599Ba8ZWpyutzH0V4Nt8j9g6ddVB1nB62ssibExRCr9RVgHTQg99BGvnxBkx9iUb18eWLwalX2WbVdg3cNQSq8oQyfIW38ott619S3ugutDkkC5h0cMDO0GWlUSz3icrC1HoTbmJEpfVfbb8mzt9LjEiOX8B6dV8I5poZwWDoJ24k0";
		String slt2 = new StringBuilder("Q4dB10tAxeAGUfFefAuAcOOFMgM6cyh33Yawmn4bABYYJErle6fR3DyF5DLwA7bPgx5kP3tlNePcybHybA599Ba8ZWpyutzH0V4Nt8j9g6ddVB1nB62ssibExRCr9RVgHTQg99BGvnxBkx9iUb18eWLwalX2WbVdg3cNQSq8oQyfIW38ott619S3ugutDkkC5h0cMDO0GWlUSz3icrC1HoTbmJEpfVfbb8mzt9LjEiOX8B6dV8I5poZwWDoJ24k0").reverse().toString();

		String input = "SES Test 2";
		String encrypted = SES.encrypt(input, key, slt1, slt2);
		String decrypted = SES.decrypt(encrypted, key, slt1, slt2);

		assertEquals(input, decrypted, "Decrypted should be equal with input");
	}

}

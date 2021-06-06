package dev.zihasz.sec4j.tests.encryption;

import dev.zihasz.sec4j.encryption.DES;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DESTest {

	@Test
	public void testDESEncryptDecrypt1() {
		String key = "T2pRnC3pDRxAdSukf6EOgAiRTTQxZ29qof36upPbdoNWMPWYIQWHtDqUiYuMPZh73B4AHTnXCgdnWiFlinpDxdltsXKQXkvM0iIBWAbPa1ZGeKuh99oJEypRjJGM75mRQSDTZN26ovPhmeLbriroDtCpwTS52apmAu9AwK7Pv6Y1wlZWaono8GYBJa2ZD2NLWHxbHn8UaYLVB2Mq8mZ0f5XxzpFwCMcWNyhzYChZ8Jm4jY59kLnhA4oQFJjyd3Vu";

		byte[] inputtext = "DES Test 2".getBytes();
		byte[] encrypted = DES.encrypt(inputtext, key.getBytes());
		byte[] decrypted = DES.decrypt(encrypted, key.getBytes());

		String in = new String(inputtext);
		String de = new String(decrypted);

		System.out.println(in);
		System.out.println(de);

		assertEquals(in, de, "Decrypted should be equal with input");
	}

	@Test
	public void test3DESEncryptDecrypt1() {
		byte[][] keys = {
				"sASS7BaIUw2Y721Qun9DS7lUePu1u9DSAIjxXI83wsVXaJmT320OOTflz9Fw3vz5Erx1ufrLTfV7iO6V6o05j2r9GbMkeuyy1ArSMlRsGpSxA9c5wNXfqUXPD09eD5aLYeBRZ92Y8uIxEsXextG2Pj5ub1Rdacig7da5ArzVvTPRFBAitV902U94xqiuXrUdAWIpe17L0Sz4wn0IiBNKJdbNvE0jCy3Qca16aVm3CmuKZvUkQmM5hDtG4ruMwsjy".getBytes(),
				"ym0QyWMf9QZhy0xx9vmh38TNaUgOcA7Z6kWHGvlWcjDF2oIS5zkMDOWPYklPuZVB3BIS9o1B8phjCGqsdGRo0Pj7Uz0UzPZtOTVF4OnaZ8kOtlIc9I8APRazPXoxMdbKY562weu1vBWbQY96oAd48uiE2yDbJUiEDpqkL3mvwG5mNDFH7rJ1Wq7LbOpYTwzpIVVOmCH4QE8QWmeGAZSmQce3lclDXa1BpMcDTrnu3O7X5Xem0pe3lwrrvK1R31kt".getBytes(),
				"M0joF0Ekk2A7OgottOszYfoNOjOVqGJLuoXQPxyVEvZu5PuJapPSPh4Aqu1gr04pa3qimX2MD4L043aksa9VbgjKp1rJNzdOWT611npC4oEoXoxytG0lg9HWZaLRmbL7WvwzmeCiiRfuIvOBCE1Fe7ES9uXjXfoGnmOScqWrPQSHhOmYGzdgSVj3caUFxyXiuHcVsSzPRDNMLEi8XeOESw6w9204s4ipsyUzjWwiVYLpJj0webV25uIQmAuq1TPS".getBytes()
		};

		byte[] inputtext = "3DES Test 2".getBytes();
		byte[] encrypted = DES.TripleDES_Encrypt(inputtext, keys);
		byte[] decrypted = DES.TripleDES_Decrypt(encrypted, keys);

		String in = new String(inputtext);
		String de = new String(decrypted);

		System.out.println(in);
		System.out.println(de);

		assertEquals(in, de, "Decrypted should be equal with input");
	}

}

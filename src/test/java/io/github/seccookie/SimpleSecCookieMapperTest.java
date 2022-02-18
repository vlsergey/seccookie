package io.github.seccookie;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import lombok.NonNull;

class SimpleSecCookieMapperTest {

	@Test
	void canEncryptAndValidateCookie() throws NoSuchAlgorithmException {
		final KeyGenerator generator = KeyGenerator.getInstance("AES");
		final @NonNull SecretKey secretKey = generator.generateKey();

		final SimpleSecCookieMapper<String> simpleSecCookieMapper = new SimpleSecCookieMapper<>(
				new SimpleSecCookieMapper.Settings<>(String::getBytes, String::new, () -> secretKey));

		final String randomString = UUID.randomUUID().toString();
		final byte[] secCookie = simpleSecCookieMapper.writeValue(randomString);
		final String decoded = simpleSecCookieMapper.readValue(secCookie);
		assertEquals(randomString, decoded);
	}

	@Test
	void modificationsWillLeadToException() throws NoSuchAlgorithmException {
		final KeyGenerator generator = KeyGenerator.getInstance("AES");
		final @NonNull SecretKey secretKey = generator.generateKey();

		final SimpleSecCookieMapper<String> simpleSecCookieMapper = new SimpleSecCookieMapper<>(
				new SimpleSecCookieMapper.Settings<>(String::getBytes, String::new, () -> secretKey));

		final String randomString = UUID.randomUUID().toString();
		final byte[] secCookie = simpleSecCookieMapper.writeValue(randomString);

		{
			final byte[] copy = Arrays.copyOf(secCookie, secCookie.length);
			copy[copy.length - 1] = (byte) (copy[copy.length - 1] + 1);
			assertThrows(WrongSecureCookieException.class, () -> simpleSecCookieMapper.readValue(copy));
		}
		{
			final byte[] copy = Arrays.copyOf(secCookie, secCookie.length + 1);
			copy[copy.length - 1] = 0;
			assertThrows(WrongSecureCookieException.class, () -> simpleSecCookieMapper.readValue(copy));
		}
	}

}

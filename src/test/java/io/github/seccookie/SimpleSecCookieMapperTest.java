package io.github.seccookie;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import io.github.seccookie.SimpleSecCookieMapper.Settings;
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

	@Test
	void supportsKeyRollingViaMultipleDecryptKeys() throws NoSuchAlgorithmException {
		final KeyGenerator generator = KeyGenerator.getInstance("AES");
		final @NonNull SecretKey secretKey1 = generator.generateKey();
		final @NonNull SecretKey secretKey2 = generator.generateKey();
		final @NonNull SecretKey secretKey3 = generator.generateKey();

		final @NonNull AtomicReference<SecretKey> keyToEncrypt = new AtomicReference<>(secretKey2);
		final @NonNull List<@NonNull SecretKey> keysToDecrypt = new ArrayList<>(2);
		keysToDecrypt.add(secretKey1);
		keysToDecrypt.add(secretKey2);

		final Settings<String> settings = new SimpleSecCookieMapper.Settings<>(String::getBytes, String::new,
				() -> keyToEncrypt.get());
		settings.setDecryptionKeysSupplier(() -> keysToDecrypt);
		final SimpleSecCookieMapper<String> mapper = new SimpleSecCookieMapper<>(settings);

		final String randomString = UUID.randomUUID().toString();
		final byte[] secCookie = mapper.writeValue(randomString);

		assertEquals(randomString, mapper.readValue(secCookie));

		// assume key configuration is SLOWLY changing between encryption and decryption
		// according to rules in README.md

		keysToDecrypt.remove(0);

		assertEquals(randomString, mapper.readValue(secCookie));

		keysToDecrypt.add(secretKey3);

		assertEquals(randomString, mapper.readValue(secCookie));

		keyToEncrypt.set(secretKey3);

		assertEquals(randomString, mapper.readValue(secCookie));
	}
}

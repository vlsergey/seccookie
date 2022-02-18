package io.github.seccookie;

import static java.lang.System.arraycopy;

import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.annotation.Nonnull;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.SneakyThrows;

/**
 * Most simple and straightforward implementation. Uses single {@link SecretKey}
 * for encryption and description. GCM encryption mode helps to protect both
 * from reading and modifications.
 * 
 * Result structure:
 * <ul>
 * <li>{@link SimpleSecCookieMapper.IV_LENGTH_BYTES} bytes for initialization
 * vector (IV)
 * <li>Cipher text, including {@link Settings#getGcmTagLength()} bytes for auth
 * tag at the end.
 * </ul>
 *
 * @param <T>
 */
public class SimpleSecCookieMapper<T> extends AbstractSecCookieMapper<T> {

	@Getter
	@Setter
	public static class Settings<T> {

		private @NonNull Function<byte @NonNull [], T> deserializer;

		private @NonNull Supplier<@NonNull Cipher> gcmCipherSupplier = new CachedProviderCipherSupplier(
				"AES/GCM/NoPadding");

		/**
		 * GCM mode tag length. 96 and 128 are usually supported.
		 */
		public int gcmTagLengthBits = 96;

		private @NonNull Supplier<@NonNull SecretKey> keySupplier;

		private @NonNull SecureRandom secureRandom = new SecureRandom();

		private @NonNull Function<T, byte @NonNull []> serializer;

		public Settings(final @NonNull Function<T, byte @NonNull []> serializer,
				final @Nonnull @NonNull Function<byte @NonNull [], T> deserializer,
				final @Nonnull @NonNull Supplier<@NonNull SecretKey> keySupplier) {
			super();
			this.serializer = serializer;
			this.deserializer = deserializer;
			this.keySupplier = keySupplier;
		}

	}

	public static final int IV_LENGTH_BYTES = 12;

	private final @NonNull Supplier<@NonNull Cipher> gcmCipherSupplier;

	private final int gcmTagLengthBits;

	private final @NonNull Supplier<@NonNull SecretKey> keySupplier;

	private final @NonNull SecureRandom secureRandom;

	public SimpleSecCookieMapper(final @Nonnull @NonNull Settings<T> settings) {
		super(settings.getSerializer(), settings.getDeserializer());

		this.gcmCipherSupplier = settings.gcmCipherSupplier;
		this.gcmTagLengthBits = settings.gcmTagLengthBits;
		this.keySupplier = settings.keySupplier;
		this.secureRandom = settings.secureRandom;
	}

	@Nonnull
	@Override
	@SneakyThrows
	protected byte @NonNull [] encryptAndSign(@Nonnull byte @NonNull [] serialized) {
		final @NonNull Cipher cipher = gcmCipherSupplier.get();
		final @NonNull SecretKey secretKey = keySupplier.get();

		final byte[] iv = new byte[IV_LENGTH_BYTES];
		secureRandom.nextBytes(iv);

		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(gcmTagLengthBits, iv));
		final byte[] cipherText = cipher.doFinal(serialized);

		final byte[] result = new byte[IV_LENGTH_BYTES + cipherText.length];
		arraycopy(iv, 0, result, 0, IV_LENGTH_BYTES);
		arraycopy(cipherText, 0, result, IV_LENGTH_BYTES, cipherText.length);
		return result;
	}

	@Override
	@SneakyThrows
	protected @Nonnull byte @NonNull [] decryptAndValidate(@Nonnull byte @NonNull [] secCookie) {
		if (secCookie.length < IV_LENGTH_BYTES + gcmTagLengthBits >> 3) {
			throw new WrongSecureCookieException(MessageFormat.format(
					"Secure cookie is too short: {0}. At least {1} bytes expected for current settings",
					secCookie.length, IV_LENGTH_BYTES + gcmTagLengthBits >> 3));
		}

		final @NonNull Cipher cipher = gcmCipherSupplier.get();
		final @NonNull SecretKey secretKey = keySupplier.get();

		cipher.init(Cipher.DECRYPT_MODE, secretKey,
				new GCMParameterSpec(gcmTagLengthBits, secCookie, 0, IV_LENGTH_BYTES));

		final byte[] plainText;
		try {
			plainText = cipher.doFinal(secCookie, IV_LENGTH_BYTES, secCookie.length - IV_LENGTH_BYTES);
		} catch (Exception exc) {
			throw new WrongSecureCookieException(exc);
		}

		return plainText;
	}

}

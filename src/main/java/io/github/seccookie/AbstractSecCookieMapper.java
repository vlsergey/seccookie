package io.github.seccookie;

import java.util.function.Function;

import javax.annotation.Nonnull;

import lombok.AllArgsConstructor;
import lombok.NonNull;

@AllArgsConstructor
public abstract class AbstractSecCookieMapper<T> implements SecCookieMapper<T> {

	private final @NonNull Function<T, byte @NonNull []> serializer;

	private final @NonNull Function<byte @NonNull [], T> deserializer;

	protected abstract byte @NonNull [] decryptAndValidate(byte @NonNull [] secCookie);

	protected abstract byte @NonNull [] encryptAndSign(byte @NonNull [] serialized);

	@Override
	public T readValue(@Nonnull byte @NonNull [] secCookie) {
		return deserializer.apply(decryptAndValidate(secCookie));
	}

	@Override
	@Nonnull
	public byte @NonNull [] writeValue(T object) {
		return encryptAndSign(serializer.apply(object));
	}

}

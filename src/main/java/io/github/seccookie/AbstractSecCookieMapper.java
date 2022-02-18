package io.github.seccookie;

import java.util.function.Function;

import javax.annotation.Nonnull;

import lombok.AllArgsConstructor;
import lombok.NonNull;

@AllArgsConstructor
public abstract class AbstractSecCookieMapper<T> implements SecCookieMapper<T> {

	private final @NonNull Function<T, byte @NonNull []> serializer;

	private final @NonNull Function<byte @NonNull [], T> deserializer;

	protected abstract byte @NonNull [] decryptAndValidate(byte @NonNull [] data);

	protected abstract byte @NonNull [] encryptAndSign(byte @NonNull [] apply);

	@Override
	public T readValue(@Nonnull byte @NonNull [] data) {
		return deserializer.apply(decryptAndValidate(data));
	}

	@Override
	@Nonnull
	public byte @NonNull [] writeValue(T object) {
		return encryptAndSign(serializer.apply(object));
	}

}

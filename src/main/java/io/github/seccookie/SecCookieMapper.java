package io.github.seccookie;

import javax.annotation.Nonnull;

import lombok.NonNull;

public interface SecCookieMapper<T> {

	@Nonnull
	byte @NonNull [] writeValue(T object);

	T readValue(@Nonnull byte @NonNull [] data);

}

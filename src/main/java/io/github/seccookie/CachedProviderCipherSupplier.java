package io.github.seccookie;

import java.security.Provider;
import java.util.function.Supplier;

import javax.annotation.Nonnull;
import javax.crypto.Cipher;

import lombok.NonNull;
import lombok.SneakyThrows;

public class CachedProviderCipherSupplier implements Supplier<@NonNull Cipher> {

	private @NonNull Provider provider;
	private @NonNull String transformation;

	@SneakyThrows
	public CachedProviderCipherSupplier(final @Nonnull @NonNull String transformation) {
		this.provider = Cipher.getInstance(transformation).getProvider();
		this.transformation = transformation;
	}

	@Override
	@SneakyThrows
	public @Nonnull @NonNull Cipher get() {
		return Cipher.getInstance(transformation, provider);
	}

}

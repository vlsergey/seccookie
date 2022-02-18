package io.github.seccookie;

public class WrongSecureCookieException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public WrongSecureCookieException(String message, Throwable cause) {
		super(message, cause);
	}

	public WrongSecureCookieException(String message) {
		super(message);
	}

}

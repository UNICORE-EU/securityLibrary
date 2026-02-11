package eu.unicore.security;

/**
 * exception thrown when authorisation fails
 */
public class AuthorisationException extends SecurityException{

	private static final long serialVersionUID = 1L;

	public AuthorisationException() {
		super();
	}

	/**
	 * @param message
	 * @param cause
	 */
	public AuthorisationException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param message
	 */
	public AuthorisationException(String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public AuthorisationException(Throwable cause) {
		super(cause);
	}

}

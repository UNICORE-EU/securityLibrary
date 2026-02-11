package eu.unicore.security;

/**
 * exception thrown when authentication fails
 */
public class AuthenticationException extends SecurityException{

	private static final long serialVersionUID = 1L;

	public AuthenticationException() {
		super();
	}

	/**
	 * @param message
	 * @param cause
	 */
	public AuthenticationException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param message
	 */
	public AuthenticationException(String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public AuthenticationException(Throwable cause) {
		super(cause);
	}

}

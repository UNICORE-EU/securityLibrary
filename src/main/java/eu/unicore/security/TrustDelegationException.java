package eu.unicore.security;

/**
 * exception thrown when trust delagation fails
 */
public class TrustDelegationException extends SecurityException{

	private static final long serialVersionUID = 1L;

	public TrustDelegationException() {
		super();
	}

	/**
	 * @param message
	 * @param cause
	 */
	public TrustDelegationException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param message
	 */
	public TrustDelegationException(String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public TrustDelegationException(Throwable cause) {
		super(cause);
	}

}

package eu.unicore.security;

/**
 * Enum with status of the signature verification.
 * @author K. Benedyczak
 */
public enum SignatureStatus 
{
	/**
	 * Signature wasn't checked for this request. It is not known
	 * if it is present or not.
	 */
	UNCHECKED,
	/**
	 * Request is unsigned.
	 */
	UNSIGNED, 
	/**
	 * Request is correctly signed.
	 */
	OK, 
	/**
	 * Request is signed but incorrectly.
	 */
	WRONG
}
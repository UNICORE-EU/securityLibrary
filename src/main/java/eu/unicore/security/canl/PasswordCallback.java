package eu.unicore.security.canl;

/**
 * Interface is used to obtain credential or truststore passwords at runtime,
 * typically by asking the user.
 * <p>
 * IMPORTANT: the implementation must handle password caching, i.e. the getPassword
 * method may be called many times during the lifetime of this object, and typically the
 * user should be asked only once (per protected Artifact Type and description combination).
 * This is implemented in the {@link CachingPasswordCallback} and typically you should simply extend this class. 
 * 
 * @author K. Benedyczak
 */
public interface PasswordCallback
{
	/**
	 * method should return password
	 * @param protectedArtifactType describes whether this is credential or truststore password 
	 * @param protectedArtifactDescription provides details about the object which is password protected
	 * as e.g. keystore file and its alias. 
	 * @return the password
	 */
	public char[] getPassword(String protectedArtifactType, String protectedArtifactDescription);
	
	/**
	 * @return whether (if credential type allows for it) a query for a separate key password should be done (if returns true)
	 * or the same passowrd as the main credential password should be used (if returns false). Applicable only for credentials 
	 * in JKS type currently. 
	 */
	public boolean askForSeparateKeyPassword();
	
	/**
	 * @return if returns true then the callback is always used regardless of properties with passwords. If false
	 * then callback is used only if the property is missing.
	 */
	public boolean ignoreProperties();
}

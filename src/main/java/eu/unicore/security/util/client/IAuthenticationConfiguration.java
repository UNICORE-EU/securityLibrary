package eu.unicore.security.util.client;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;


/**
 * Implementation of this interface provides data necessary for 
 * setting up transport level security and HTTP authentication.
 * 
 * @author K. Benedyczak
 */
public interface IAuthenticationConfiguration
{
	/**
	 * Returns true if the client-side TLS authentication should be done.
	 * If false then local credential retrieval method 
	 * is not used at all.
	 * @return
	 */
	public boolean doSSLAuthn();

	/**
	 * 
	 * @return local credential, used if doSSLAuthn returns true
	 */
	public X509Credential getCredential();
	
	/**
	 * Returns certificates validator.
	 * @return
	 */
	public X509CertChainValidator getValidator();
	
	/**
	 * Returns true if HTTP BASIC Auth should be used.
	 * @return
	 */
	public boolean doHttpAuthn();
	/**
	 * Returns HTTP BASIC Auth user. Required if doHttpAuthn is true.
	 * @return
	 */
	public String getHttpUser();
	/**
	 * Returns HTTP BASIC Auth user's password. Required if doHttpAuthn is true.
	 * @return
	 */
	public String getHttpPassword();
	
	/**
	 * Cloning support is mandatory
	 */
	public IAuthenticationConfiguration clone();
}

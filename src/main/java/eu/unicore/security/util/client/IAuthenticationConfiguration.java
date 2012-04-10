package eu.unicore.security.util.client;

import eu.unicore.security.util.IAuthnAndTrustConfiguration;


/**
 * Implementation of this interface provides data necessary for 
 * setting up transport level security and HTTP authentication on client side.
 * It extends {@link IAuthnAndTrustConfiguration} by providing possibility to 
 * perform HTTP authentication (what is very rarely used in UNICORE) and to turn on/off
 * SSL authentication. Typical implementation is the {@link DefaultAuthnConfigurationImpl} 
 * and its children.
 * 
 * @author K. Benedyczak
 */
public interface IAuthenticationConfiguration extends IAuthnAndTrustConfiguration
{
	/**
	 * Returns true if the client-side TLS authentication should be done.
	 * If false then local credential retrieval method 
	 * is not used at all.
	 * @return
	 */
	public boolean doSSLAuthn();

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

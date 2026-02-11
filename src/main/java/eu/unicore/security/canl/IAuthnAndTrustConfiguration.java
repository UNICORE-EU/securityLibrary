package eu.unicore.security.canl;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.X509Credential;


/**
 * Interface providing access to all security related settings for a UNICORE client or server:
 * truststore configuration and credentials. 
 * 
 * @author K. Benedyczak
 */
public interface IAuthnAndTrustConfiguration extends Cloneable
{
	/**
	 * 
	 * @return Object used to verify certificate chains
	 */
	public X509CertChainValidatorExt getValidator();
	
	/**
	 * 
	 * @return object used to provide local credentias
	 */
	public X509Credential getCredential();
	
	/**
	 * 
	 * @return cloned object
	 */
	public IAuthnAndTrustConfiguration clone();
}

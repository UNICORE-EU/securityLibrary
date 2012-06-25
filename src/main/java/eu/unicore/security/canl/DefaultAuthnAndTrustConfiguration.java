/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jun 13, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.canl;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;


/**
 * A default implementation of the {@link IAuthenticationConfiguration} interface
 * which can be used to manually configure all aspects of the interface with constructor parameters.
 * 
 * @author golbi
 */
public class DefaultAuthnAndTrustConfiguration implements IAuthnAndTrustConfiguration
{
	private X509CertChainValidator validator;
	private X509Credential credential;
	
	/**
	 * Only default settings, i.e. no security.
	 */
	public DefaultAuthnAndTrustConfiguration()
	{
	}

	/**
	 * This constructor is the typical for UNICORE: ssl authN is on, http authn is off. 
	 * @param validator
	 * @param credential
	 */
	public DefaultAuthnAndTrustConfiguration(X509CertChainValidator validator, X509Credential credential)
	{
		this.validator = validator;
		this.credential = credential;
	}

	/**
	 * @return the validator
	 */
	@Override
	public X509CertChainValidator getValidator()
	{
		return validator;
	}

	/**
	 * @param validator the validator to set
	 */
	public void setValidator(X509CertChainValidator validator)
	{
		this.validator = validator;
	}

	/**
	 * @return the credential
	 */
	@Override
	public X509Credential getCredential()
	{
		return credential;
	}

	/**
	 * @param credential the credential to set
	 */
	public void setCredential(X509Credential credential)
	{
		this.credential = credential;
	}

	/**
	 * Note - credential and validator objects are not cloned - are copied by reference.
	 * This doesn't affect threading (both are thread safe). Credential is usually immutable.
	 * Changes to validator settings will be visible also in the validator of the cloned object.
	 */
	@Override
	public IAuthnAndTrustConfiguration clone()
	{
		DefaultAuthnAndTrustConfiguration ret = new DefaultAuthnAndTrustConfiguration();
		ret.setCredential(credential);
		ret.setValidator(validator);
		return ret;
	}
}

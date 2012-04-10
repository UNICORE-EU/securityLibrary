/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jun 13, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.util.client;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;


/**
 * This is a helper implementation of {@link IAuthenticationConfiguration} interface
 * which can be used to setup socket using {@link X509CertChainValidator} and
 * {@link X509Credential}, without HTTP authentication and with SSL client-side authentication turned on.
 * 
 * @author golbi
 */
public class DefaultAuthnConfigurationImpl extends AbstractSecurityConfigurationImpl
{
	private X509CertChainValidator validator;
	private X509Credential credential;
	
	public DefaultAuthnConfigurationImpl(X509CertChainValidator validator, X509Credential credential)
	{
		this.validator = validator;
		this.credential = credential;
	}

	@Override
	public X509Credential getCredential()
	{
		return credential;
	}
	
	@Override
	public X509CertChainValidator getValidator()
	{
		return validator;
	}

	public IAuthenticationConfiguration clone()
	{
		return new DefaultAuthnConfigurationImpl(validator, credential);
	}
}

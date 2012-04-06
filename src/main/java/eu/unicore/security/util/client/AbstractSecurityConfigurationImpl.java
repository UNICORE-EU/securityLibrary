/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.util.client;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;

/**
 * Do nothing implementation of security configuration. Useful for subclassing.
 * This implementation provides absolutely no security (trusting everything, not
 * authenticating with anything).
 * @author K. Benedyczak
 */
public abstract class AbstractSecurityConfigurationImpl implements IAuthenticationConfiguration
{
	@Override
	public boolean doHttpAuthn()
	{
		return false;
	}

	@Override
	public boolean doSSLAuthn()
	{
		return false;
	}

	@Override
	public String getHttpPassword()
	{
		return null;
	}

	@Override
	public String getHttpUser()
	{
		return null;
	}

	@Override
	public X509Credential getCredential()
	{
		return null;
	}
	
	@Override
	public X509CertChainValidator getValidator()
	{
		return new BinaryCertChainValidator(true);
	}

	public abstract IAuthenticationConfiguration clone();
}

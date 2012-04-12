/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.security.util.client.DefaultClientConfiguration;
import eu.unicore.security.util.client.IClientConfiguration;

/**
 * @author K. Benedyczak
 */
public class MockSecurityConfig extends DefaultClientConfiguration
{
	public static final String HTTP_PASSWD = "123";
	public static final String HTTP_USER = "qwer";
	
	public static final String KS = "src/test/resources/client/client.jks";
	public static final String KS_PASSWD = "the!client";

	public static final String KS_ALIAS = "mykey";
	public static final String KS_ALIAS_GW = "gw";
	public static final String KS_ALIAS_WRONG = "mykey_wrong";

	private boolean correctSSLAuthN;
	private boolean doHTTPAuthN;
	private boolean doSSLAuthN;
	private X509CertChainValidator validator;
	private X509Credential credential;
	
	public MockSecurityConfig(boolean doHTTPAuthN,
			boolean doSSLAuthN, boolean correctSSLAuthN) throws Exception
	{
		this.doHTTPAuthN = doHTTPAuthN;
		this.doSSLAuthN = doSSLAuthN;
		this.correctSSLAuthN = correctSSLAuthN;
		if (doSSLAuthN)
		{
			credential = new KeystoreCredential(KS, 
				KS_PASSWD.toCharArray(), KS_PASSWD.toCharArray(), 
				correctSSLAuthN ? KS_ALIAS: KS_ALIAS_WRONG, 
				"JKS");
			validator = new KeystoreCertChainValidator(KS, KS_PASSWD.toCharArray(), 
				"JKS", -1);
		}
	}

	@Override
	public boolean doHttpAuthn()
	{
		return doHTTPAuthN;
	}

	@Override
	public boolean doSSLAuthn()
	{
		return doSSLAuthN;
	}

	@Override
	public String getHttpPassword()
	{
		return HTTP_PASSWD;
	}

	@Override
	public String getHttpUser()
	{
		return HTTP_USER;
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
	
	@Override
	public IClientConfiguration clone()
	{
		try
		{
			return new MockSecurityConfig(doHTTPAuthN, 
					doSSLAuthN, correctSSLAuthN);
		} catch (Exception e)
		{
			throw new RuntimeException("Can't clone!");
		}
	}
}

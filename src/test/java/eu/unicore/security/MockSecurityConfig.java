/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

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
	
	public MockSecurityConfig(boolean doHTTPAuthN,
			boolean doSSLAuthN, boolean correctSSLAuthN) throws Exception
	{
		setHttpAuthn(doHTTPAuthN);
		setSslAuthn(doSSLAuthN);
		this.correctSSLAuthN = correctSSLAuthN;
		setHttpPassword(HTTP_PASSWD);
		setHttpUser(HTTP_USER);
		if (doSSLAuthN)
		{
			setCredential(new KeystoreCredential(KS, 
				KS_PASSWD.toCharArray(), KS_PASSWD.toCharArray(), 
				correctSSLAuthN ? KS_ALIAS: KS_ALIAS_WRONG, 
				"JKS"));
		}
		setValidator(new KeystoreCertChainValidator(KS, KS_PASSWD.toCharArray(), 
				"JKS", -1));
	}

	@Override
	public IClientConfiguration clone()
	{
		try
		{
			MockSecurityConfig ret = new MockSecurityConfig(doHttpAuthn(), 
					doSSLAuthn(), correctSSLAuthN);
			cloneTo(ret);
			return ret;
		} catch (Exception e)
		{
			throw new RuntimeException("Can't clone!");
		}
	}
}

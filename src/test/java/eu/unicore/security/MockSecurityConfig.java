/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

import eu.unicore.security.util.client.IAuthenticationConfiguration;

/**
 * @author K. Benedyczak
 */
public class MockSecurityConfig implements IAuthenticationConfiguration
{
	public static final String HTTP_PASSWD = "123";
	public static final String HTTP_USER = "qwer";
	
	public static final String KS = "src/test/resources/client/client.jks";
	public static final String KS_PASSWD = "the!client";

	public static final String KS_ALIAS = "mykey";
	public static final String KS_ALIAS_GW = "gw";
	public static final String KS_ALIAS_WRONG = "mykey_wrong";
	

	
	private boolean doHTTPAuthN;
	private boolean doSSLAuthN, correctSSLAuthN;
	
	private KeyStore ks;
	
	
	public MockSecurityConfig(boolean doHTTPAuthN,
			boolean doSSLAuthN, boolean correctSSLAuthN) throws Exception
	{
		this.doHTTPAuthN = doHTTPAuthN;
		this.doSSLAuthN = doSSLAuthN;
		this.correctSSLAuthN = correctSSLAuthN;
		loadKeystore();
	}

	private void loadKeystore() throws Exception
	{
		ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream(KS), KS_PASSWD.toCharArray());
	}
	
	public String getCertDN(String alias) throws Exception
	{
		X509Certificate cert = (X509Certificate) ks.getCertificate(
				alias);
		return cert.getSubjectX500Principal().getName();
		
	}

	public X509Certificate getUserCert(String alias) throws Exception
	{
		return (X509Certificate) ks.getCertificate(alias);
		
	}
	
	public PrivateKey getUserKey(String alias) throws Exception
	{
		return (PrivateKey) ks.getKey(alias,
				KS_PASSWD.toCharArray());
	}

	public boolean doHttpAuthn()
	{
		return doHTTPAuthN;
	}

	public boolean doSSLAuthn()
	{
		return doSSLAuthN;
	}

	public String getHttpPassword()
	{
		return HTTP_PASSWD;
	}

	public String getHttpUser()
	{
		return HTTP_USER;
	}

	public String getKeystore()
	{
		return KS;
	}

	public String getKeystoreAlias()
	{
		if (correctSSLAuthN)
			return KS_ALIAS;
		return KS_ALIAS_WRONG;
	}

	public String getKeystoreKeyPassword()
	{
		return KS_PASSWD;
	}

	public String getKeystorePassword()
	{
		return KS_PASSWD;
	}

	public String getKeystoreType()
	{
		return "JKS";
	}

	public String getTruststore()
	{
		return KS;
	}

	public String getTruststorePassword()
	{
		return KS_PASSWD;
	}

	public String getTruststoreType()
	{
		return "JKS";
	}

	public IAuthenticationConfiguration clone()
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

	public SSLContext getSSLContext()
	{
		return null;
	}
}

/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jun 13, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.util.client;

import javax.net.ssl.SSLContext;

/**
 * This is a helper implementation of {@link IAuthenticationConfiguration} interface
 * which can be used in a number of common situations:
 * <ul>
 * <li> no SSL and no HTTP auth
 * <li> no SSL and HTTP auth
 * <li> SSL initialized with {@link SSLContext} and no HTTP auth
 * <li> SSL initialized with {@link SSLContext} and HTTP auth 
 * </ul>
 * @author golbi
 */
public class SimpleAuthnConfigurationImpl extends AbstractSecurityConfigurationImpl
{
	private SSLContext ctx;
	private String httpUser, httpPasswd;
	
	/**
	 * Configuration without SSL and without HTTP authn
	 */
	public SimpleAuthnConfigurationImpl()
	{
		this(null, null, null);
	}
	
	/**
	 * Configuration without SSL and with HTTP authn
	 * @param httpUser
	 * @param httpPasswd
	 */
	public SimpleAuthnConfigurationImpl(String httpUser, String httpPasswd)
	{
		this(null, httpUser, httpPasswd);
	}
	
	/**
	 * Configuration with SSL and without HTTP authn
	 * @param sslContext
	 */
	public SimpleAuthnConfigurationImpl(SSLContext sslContext)
	{
		this(sslContext, null, null);
	}

	/**
	 * Configuration with SSL and with HTTP authn
	 * @param sslContext
	 * @param httpUser
	 * @param httpPasswd
	 */
	public SimpleAuthnConfigurationImpl(SSLContext sslContext, 
			String httpUser, String httpPasswd)
	{
		this.ctx = sslContext;
		this.httpUser = httpUser;
		this.httpPasswd = httpPasswd;
	}
	
	public boolean doHttpAuthn()
	{
		return httpUser != null;
	}

	public boolean doSSLAuthn()
	{
		return false;
	}

	public String getHttpPassword()
	{
		return httpPasswd;
	}

	public String getHttpUser()
	{
		return httpUser;
	}

	public SSLContext getSSLContext()
	{
		return ctx;
	}

	public Object clone()
	{
		return new SimpleAuthnConfigurationImpl(ctx, httpUser, httpPasswd);
	}
}

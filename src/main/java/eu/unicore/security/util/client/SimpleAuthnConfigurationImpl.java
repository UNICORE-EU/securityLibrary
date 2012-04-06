/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jun 13, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.util.client;


/**
 * This is a helper implementation of {@link IAuthenticationConfiguration} interface
 * which can be used in a number of common situations:
 * <ul>
 * <li> no SSL and no HTTP auth
 * <li> no SSL and HTTP auth
 * </ul>
 * @author golbi
 */
public class SimpleAuthnConfigurationImpl extends AbstractSecurityConfigurationImpl
{
	private String httpUser, httpPasswd;
	
	/**
	 * Configuration without SSL and without HTTP authn
	 */
	public SimpleAuthnConfigurationImpl()
	{
		this(null, null);
	}
	
	/**
	 * Configuration without SSL and with HTTP authn
	 * @param httpUser
	 * @param httpPasswd
	 */
	public SimpleAuthnConfigurationImpl(String httpUser, String httpPasswd)
	{
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

	public IAuthenticationConfiguration clone()
	{
		return new SimpleAuthnConfigurationImpl(httpUser, httpPasswd);
	}
}

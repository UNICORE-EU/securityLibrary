/*
 * Copyright (c) 2010 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 16-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.util.httpclient;

import eu.unicore.security.canl.IAuthnAndTrustConfiguration;

/**
 * Extension of {@link IAuthnAndTrustConfiguration},
 * provides (mostly) security related settings, useful for the client side:
 * <ul>
 *  <li> whether to initialize SSL or not
 *  <li> whether to do client-side SSL authentication
 *  <li> whether to check server hostnames
 * </ul>
 * In the typical UNICORE-related cases, the {@link IClientConfiguration} interface is
 * the better choice. This one is used e.g. in case of XNJS-to-TSI communication.
 * @author golbi
 */
public interface IPlainClientConfiguration extends IAuthnAndTrustConfiguration
{
	/**
	 * Makes a copy of this object.
	 */
	public IPlainClientConfiguration clone();
	
	/**
	 * Returns true if SSL mode is enabled.
	 */
	public boolean isSslEnabled();
	
	/**
	 * Returns true if the client-side TLS authentication should be done.
	 * If false then the local credential won't be used.
	 */
	public boolean doSSLAuthn();

	/**
	 * whether to check if server hostname matches server's certificate
	 */
	public ServerHostnameCheckingMode getServerHostnameCheckingMode();
}

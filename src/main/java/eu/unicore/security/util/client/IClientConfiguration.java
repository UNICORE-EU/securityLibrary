/*
 * Copyright (c) 2010 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 16-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.util.Map;
import java.util.Properties;

import eu.unicore.security.util.IAuthnAndTrustConfiguration;
import eu.unicore.security.util.client.HttpUtils;

/**
 * Extension of {@link IAuthnAndTrustConfiguration},
 * provides (mostly) security related settings, useful for the client side:
 * <ul>
 *  <li> whether to initialize SSL or not
 *  <li> whether to do client-side SSL authentication
 *  <li> whether to perform HTTP authentication and settings for it
 *  <li> whether to disable digital body signing
 *  <li> whether to check server hostnames
 *  <li> list of outgoing and incoming handlers
 *  <li> classloader to be used in case of loading handler classes
 *  <li> settings to automatically initialize ETD for outgoing messages.
 *  <li> additional settings for handlers.
 *  <li> additional properties for setting up HTTP client
 * </ul>
 * 
 * @author golbi
 */
public interface IClientConfiguration extends IAuthnAndTrustConfiguration
{
	/**
	 * Makes a copy of these properties.
	 */
	public IClientConfiguration clone();
	
	/**
	 * Returns true if the client-side TLS authentication should be done.
	 * If false then local credential retrieval method 
	 * is not used at all.
	 * @return
	 */
	public boolean doSSLAuthn();

	/**
	 * whether to check if server hostname matches server's certificate
	 * @return
	 */
	public ServerHostnameCheckingMode getServerHostnameCheckingMode();
	
	/**
	 * Returns true if HTTP BASIC Auth should be used.
	 * @return
	 */
	public boolean doHttpAuthn();
	
	/**
	 * Returns HTTP BASIC Auth user. Required if doHttpAuthn is true.
	 * @return
	 */
	public String getHttpUser();
	
	/**
	 * Returns HTTP BASIC Auth user's password. Required if doHttpAuthn is true.
	 * @return
	 */
	public String getHttpPassword();
	
	/**
	 * Returns the names of the security handler classes for outbound messages,
	 * separated by a single space.
	 */
	public String getOutHandlerClassNames();
	
	/**
	 * Returns the names of the security handler classes for incoming messages,
	 * separated by a single space.
	 */
	public String getInHandlerClassNames();
	
	/**
	 * Get the classloader to be used e.g. for dynamically loading security handlers.
	 */
	public ClassLoader getClassLoader();
	
	/**
	 * Returns true if SSL mode is enabled.
	 */
	public boolean isSslEnabled();
	
	/**
	 * Digital signature mechanism can be disabled with this method returning false.
	 */
	public boolean doSignMessage();

	/**
	 * Returns an object with setup of ETD to be used in outgoing calls.
	 */
	public ETDClientSettings getETDSettings();
	
	/**
	 * Returns additional settings which are used to set up the client call
	 * (e.g., HTTP client proxy settings or additional security handler settings)
	 * 
	 * @return see above
	 * @see HttpUtils
	 * @see XFireClientFactory
	 */
	public Properties getExtraSettings();
	
	/**
	 * For outgoing calls, get extra security information. This map is used whenever 
	 * specialized objects are to be passed to the additional <b>handlers</b> which
	 * were configured by this class.
	 */
	public Map<String,Object> getExtraSecurityTokens();
}

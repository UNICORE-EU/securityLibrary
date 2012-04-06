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

import eu.unicore.security.util.client.HttpUtils;
import eu.unicore.security.util.client.IAuthenticationConfiguration;

/**
 * Provides additional to pure security settings for the client:
 * <ul>
 *  <li> whether to initialize SSL or not
 *  <li> list of outgoing and incoming handlers
 *  <li> classloader to be used in case of loading handler classes
 *  <li> settings to automatically initialize signing of outgoing messages.
 *  <li> settings to automatically initialize ETD for outgoing messages.
 * </ul>
 * 
 * @author golbi
 */
public interface IClientProperties extends IAuthenticationConfiguration
{
	/**
	 * Makes a copy of these properties.
	 */
	public IClientProperties clone();
	
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

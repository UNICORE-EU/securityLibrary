/*
 * Copyright (c) 2010 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 16-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.util.Properties;

import eu.unicore.security.util.client.HttpUtils;
import eu.unicore.security.util.client.IAuthenticationConfiguration;

/**
 * Provides additional to pure security settings for the client:
 * <ul>
 *  <li> whether to initialize SSL or not
 *  <li> list of outgoing and incoming handlers
 *  <li> classloader to be used in case of loading handler classes 
 * </ul>
 * 
 * TODO - this class does not fit in this module. It is here only as it is extended 
 * in use-core. Should be moved somewhere out of here.
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
	 * Returns additional settings which are used to set up HTTP client.
	 * @return see above
	 * @see HttpUtils
	 * @see XFireClientFactory
	 */
	public Properties getExtraSettings();
}

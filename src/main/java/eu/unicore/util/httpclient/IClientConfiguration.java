/*
 * Copyright (c) 2010 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 16-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.util.httpclient;

import java.util.Map;
import java.util.Properties;

/**
 * Extension of {@link IPlainClientConfiguration},
 * provides (mostly) security related settings, useful for the client side. This
 * interface adds settings relevant for HTTP and WS clients, and therefore is the 
 * the most commonly used interface for setting client side in UNICORE.
 * It allows to configure:
 * <ul>
 *  <li> whether to perform HTTP authentication and settings for it
 *  <li> whether to disable digital body signing
 *  <li> list of outgoing and incoming handlers
 *  <li> classloader to be used in case of loading handler classes
 *  <li> settings to automatically initialize ETD for outgoing messages.
 *  <li> additional settings for handlers.
 *  <li> additional properties for setting up HTTP client
 * </ul>
 * 
 * @author golbi
 */
public interface IClientConfiguration extends IPlainClientConfiguration
{
	/**
	 * Makes a copy of this object.
	 */
	public IClientConfiguration clone();
	
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
	 * Returns the handler classes for outbound messages. Those classes in general 
	 * are used only in XFire stack.
	 */
	public String[] getOutHandlerClassNames();
	
	/**
	 * Returns the handler classes for incoming messages. Those classes in general 
	 * are used only in XFire stack.
	 */
	public String[] getInHandlerClassNames();
	
	/**
	 * Get the classloader to be used e.g. for dynamically loading security handlers.
	 */
	public ClassLoader getClassLoader();
	
	/**
	 * Digital signature mechanism can be disabled with this method returning false.
	 */
	public boolean doSignMessage();

	/**
	 * Returns an object with setup of ETD to be used in outgoing calls.
	 */
	public ETDClientSettings getETDSettings();
	
	/**
	 * Returns additional settings which are used to set up the client call,
	 * e.g. additional security handler settings.
	 * 
	 * @return see above
	 * @deprecated - don't use, will be removed. repalaced bny the {@link #getHttpClientProperties()}
	 */
	@Deprecated
	public Properties getExtraSettings();
	
	/**
	 * @return settings for the HTTP client.
	 */
	public HttpClientProperties getHttpClientProperties();
	
	/**
	 * For outgoing calls, get extra security information. This map is used whenever 
	 * specialized objects are to be passed to the additional <b>handlers</b> which
	 * were configured by this class.
	 */
	public Map<String,Object> getExtraSecurityTokens();
	
	/**
	 * returns true if messages should be logged
	 * @return
	 */
	public boolean isMessageLogging();
	
}

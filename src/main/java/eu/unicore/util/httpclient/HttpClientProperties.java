/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;
import eu.unicore.util.configuration.PropertyMD.DocumentationCategory;

/**
 * Configuration settings of the HTTP client, used by {@link HttpUtils}.
 * 
 * Typically not used directly - all those properties are wrapped and exposed by {@link ClientProperties}
 * 
 * @author K. Benedyczak
 */
public class HttpClientProperties extends PropertiesHelper
{
	private static final Logger log = Log.getLogger(Log.CONFIGURATION, HttpClientProperties.class);
	
	public static final String PREFIX = "http.";
	
	/** If true then connection will be closed immediately after serving the request */
	public static final String CONNECTION_CLOSE = "connection-close";
	/** Maximum number of redirects to take. Set to a non positive value to disable automatic redirects. */
	public static final String HTTP_MAX_REDIRECTS = "maxRedirects";
	/** Space delimited list of hosts for which HTTP proxy shouldn't be used */
	public static final String HTTP_NON_PROXY_HOSTS = "nonProxyHosts";
	/** HTTP proxy host */
	public static final String HTTP_PROXY_HOST = "proxyHost";
	/** HTTP proxy port */
	public static final String HTTP_PROXY_PORT = "proxyPort";
	/** HTTP proxy user name */
	public static final String HTTP_PROXY_USER = "proxy.user";
	/** HTTP proxy password */
	public static final String HTTP_PROXY_PASS = "proxy.password";
	public static final String MAX_HOST_CONNECTIONS = "maxPerRoute";
	public static final String MAX_TOTAL_CONNECTIONS = "maxTotal";
	/** socket read timeout for HTTP */
	public static final String SO_TIMEOUT = "socket.timeout";
	/** timeout for creating new HTTP connections */
	public static final String CONNECT_TIMEOUT = "connection.timeout";
	
	public static final String ALLOW_CIRCULAR_REDIRECTS = "allowCircularRedirects";
	
	public final static Map<String, PropertyMD> META = new HashMap<String, PropertyMD>();
	static 
	{
		DocumentationCategory proxyCat = new DocumentationCategory("HTTP proxy settings", "2");
		DocumentationCategory httpCat = new DocumentationCategory("HTTP client settings", "1");
		
		META.put(CONNECTION_CLOSE, new PropertyMD("false").setCategory(httpCat).
				setDescription("If set to true then the client will send connection close header, " +
						"so the server will close the socket."));
		META.put(HTTP_MAX_REDIRECTS, new PropertyMD("3").setCategory(httpCat).
				setDescription("Maximum number of allowed HTTP redirects."));
		META.put(MAX_HOST_CONNECTIONS, new PropertyMD("6").setCategory(httpCat).
				setDescription("How many connections per host can be made. " +
						"Note: this is a limit for a single client object instance."));
		META.put(MAX_TOTAL_CONNECTIONS, new PropertyMD("20").setCategory(httpCat).
				setDescription("How many connections in total can be made. " +
						"Note: this is a limit for a single client object instance."));
		META.put(SO_TIMEOUT, new PropertyMD("20000").setCategory(httpCat).
				setDescription("Socket timeout (ms)"));
		META.put(CONNECT_TIMEOUT, new PropertyMD("20000").setCategory(httpCat).
				setDescription("Timeout for the connection establishing (ms)"));
		META.put(ALLOW_CIRCULAR_REDIRECTS, new PropertyMD("false").setHidden().setCategory(httpCat).
				setDescription("If true then circular redirects are allowed."));

		META.put(HTTP_NON_PROXY_HOSTS, new PropertyMD().setCategory(proxyCat).
				setDescription("Space (single) separated list of hosts, for which the HTTP proxy should not be used."));
		META.put(HTTP_PROXY_HOST, new PropertyMD().setCategory(proxyCat).
				setDescription("If set then the HTTP proxy will be used, with this hostname."));
		META.put(HTTP_PROXY_PORT, new PropertyMD().setCategory(proxyCat).
				setDescription("HTTP proxy port. If not defined then system property is consulted, and as a final fallback 80 is used."));
		META.put(HTTP_PROXY_USER, new PropertyMD().setCategory(proxyCat).
				setDescription("Relevant only when using HTTP proxy: defines username for authentication to the proxy."));
		META.put(HTTP_PROXY_PASS, new PropertyMD().setCategory(proxyCat).
				setDescription("Relevant only when using HTTP proxy: defines password for authentication to the proxy."));

	}
	
	public HttpClientProperties(String prefix, Properties properties) throws ConfigurationException
	{
		super(prefix, properties, META, log);
	}	

	public HttpClientProperties(Properties properties) throws ConfigurationException
	{
		super(PREFIX, properties, META, log);
	}	
}

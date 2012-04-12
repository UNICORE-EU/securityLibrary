/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import eu.unicore.security.util.AuthnAndTrustProperties;
import eu.unicore.security.util.ConfigurationException;
import eu.unicore.security.util.CredentialProperties;
import eu.unicore.security.util.FilePropertiesHelper;
import eu.unicore.security.util.Log;
import eu.unicore.security.util.PropertiesHelper;
import eu.unicore.security.util.TruststoreProperties;

/**
 * Properties based implementation of {@link IClientConfiguration}.
 * Allows to configure all client-side security settings from a single properties source.
 * Several settings can be only configured via API setters, not from properties:
 * <ul>
 *  <li> classLoader
 *  <li> etdSettings
 *  <li> extraSettings
 *  <li> extraSecurityTokens
 * </ul>
 * @author K. Benedyczak
 */
public class ClientProperties extends DefaultClientConfiguration
{
	private static final Logger log = Log.getLogger(Log.SECURITY, ClientProperties.class);
	public static final String DEFAULT_PREFIX = "client.";
	
	public static final String PROP_HTTP_AUTHN_ENABLED = "httpAuthnEnabled";
	public static final String PROP_HTTP_USER = "httpUser";
	public static final String PROP_HTTP_PASSWORD = "httpPassword";
	public static final String PROP_SSL_ENABLED = "sslEnabled";
	public static final String PROP_SSL_AUTHN_ENABLED = "sslAuthnEnabled";
	public static final String PROP_MESSAGE_SIGNING_ENABLED = "digitalSigningEnabled";
	public static final String PROP_IN_HANDLERS = "inHandlers";
	public static final String PROP_OUT_HANDLERS = "outHandlers";

	public final static Map<String, String> DEFAULTS = new HashMap<String, String>();
	public final static Map<String, String> MANDATORY = new HashMap<String, String>();
	static 
	{
		DEFAULTS.put(PROP_HTTP_AUTHN_ENABLED, "false");
		DEFAULTS.put(PROP_HTTP_PASSWORD, "");
		DEFAULTS.put(PROP_HTTP_USER, "");
		DEFAULTS.put(PROP_IN_HANDLERS, "");
		DEFAULTS.put(PROP_MESSAGE_SIGNING_ENABLED, "true");
		DEFAULTS.put(PROP_OUT_HANDLERS, "");
		DEFAULTS.put(PROP_SSL_AUTHN_ENABLED, "true");
		DEFAULTS.put(PROP_SSL_ENABLED, "true");
	}

	//all those constructors sucks a bit- but there is no multi inheritance in Java, 
	//so we can't reuse code from AuthAndTrustProperties...
	
	public ClientProperties(String file) throws IOException, ConfigurationException
	{
		this(new File(file));
	}

	public ClientProperties(File file) throws IOException, ConfigurationException
	{
		this(FilePropertiesHelper.load(file));
	}
	
	public ClientProperties(String file, String trustPrefix, String credPrefix) 
			throws IOException, ConfigurationException
	{
		this(new File(file), trustPrefix, credPrefix);
	}

	public ClientProperties(File file, String trustPrefix, String credPrefix) 
			throws IOException, ConfigurationException
	{
		this(FilePropertiesHelper.load(file), trustPrefix, credPrefix, DEFAULT_PREFIX);
	}
	
	public ClientProperties(Properties p) throws ConfigurationException
	{
		this(p, TruststoreProperties.DEFAULT_PREFIX, CredentialProperties.DEFAULT_PREFIX, DEFAULT_PREFIX);
	}
	
	public ClientProperties(Properties p, String trustPrefix, String credPrefix, String clientPrefix) 
			throws ConfigurationException
	{
		AuthnAndTrustProperties helper = new AuthnAndTrustProperties(p, trustPrefix, credPrefix);
		setValidator(helper.getValidator());
		setCredential(helper.getCredential());
		PropertiesHelper properties = new PropertiesHelper(clientPrefix, p, DEFAULTS, null, log);
		setSslEnabled(properties.getBooleanValue(PROP_SSL_ENABLED));
		if (isSslEnabled()) 
		{
			setSslAuthn(properties.getBooleanValue(PROP_SSL_AUTHN_ENABLED));
		}
		setDoSignMessage(properties.getBooleanValue(PROP_MESSAGE_SIGNING_ENABLED));
		setHttpAuthn(properties.getBooleanValue(PROP_HTTP_AUTHN_ENABLED));
		if (doHttpAuthn())
		{
			setHttpPassword(properties.getValue(PROP_HTTP_PASSWORD, true, true));
			setHttpUser(properties.getValue(PROP_HTTP_USER));
		}
		setInHandlerClassNames(properties.getValue(PROP_IN_HANDLERS));
		setOutHandlerClassNames(properties.getValue(PROP_OUT_HANDLERS));
	}
}

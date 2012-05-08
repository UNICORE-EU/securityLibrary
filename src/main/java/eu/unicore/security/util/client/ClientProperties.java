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
import eu.unicore.security.util.IAuthnAndTrustConfiguration;
import eu.unicore.security.util.Log;
import eu.unicore.security.util.PropertiesHelper;
import eu.unicore.security.util.PropertyMD;
import eu.unicore.security.util.TruststoreProperties;

/**
 * Properties based implementation of {@link IClientConfiguration}.
 * Allows to configure all client-side security settings from a single properties source.
 * Several settings can be only configured via API setters, not from properties:
 * <ul>
 *  <li> classLoader
 *  <li> etdSettings
 *  <li> extraSecurityTokens
 * </ul>
 * <p>
 * If <i>not</i> using the most low level constructors 
 * ({@link #ClientProperties(Properties, IAuthnAndTrustConfiguration)} or
 * {@link #ClientProperties(Properties, String, IAuthnAndTrustConfiguration)})
 * this class by default initializes {@link IAuthnAndTrustConfiguration} 
 * (the interface is implemented by this class), i.e. credential and validator, using
 * {@link AuthnAndTrustProperties} implementation. 
 * However if SSL is disabled, credential and validator are initialized only optionally,
 * and if SSL authentication is disabled the credential initialization need not to be correct.
 * 
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
	public static final String PROP_SERVER_HOSTNAME_CHECKING = "serverHostnameChecking";
	
	public static final String EXTRA_HTTP_LIB_PROPERTIES_PREFIX = "http.";
	

	public final static Map<String, PropertyMD> META = new HashMap<String, PropertyMD>();
	static 
	{
		META.put(PROP_HTTP_AUTHN_ENABLED, new PropertyMD("false"));
		META.put(PROP_HTTP_PASSWORD, new PropertyMD("").setSecret());
		META.put(PROP_HTTP_USER, new PropertyMD(""));
		META.put(PROP_IN_HANDLERS, new PropertyMD(""));
		META.put(PROP_MESSAGE_SIGNING_ENABLED, new PropertyMD("true"));
		META.put(PROP_OUT_HANDLERS, new PropertyMD(""));
		META.put(PROP_SSL_AUTHN_ENABLED, new PropertyMD("true"));
		META.put(PROP_SSL_ENABLED, new PropertyMD("true"));
		META.put(PROP_SERVER_HOSTNAME_CHECKING, new PropertyMD(ServerHostnameCheckingMode.WARN));
	}

	//all those constructors suck a bit- but there is no multi inheritance in Java, 
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
		this(p, clientPrefix, getDefaultAuthnAndTrust(p, trustPrefix, credPrefix, clientPrefix));
	}

	public ClientProperties(Properties p, IAuthnAndTrustConfiguration authAndTrust) 
			throws ConfigurationException
	{
		this(p, DEFAULT_PREFIX, authAndTrust);
	}

	/**
	 * Load cred/validator settings. If some SSL settings are optional, then do not force the loading 
	 * of the not strictly required artifacts. However a try to load what is configured is made always.
	 * @param p
	 * @param trustPrefix
	 * @param credPrefix
	 * @param clientPrefix
	 * @return
	 */
	private static IAuthnAndTrustConfiguration getDefaultAuthnAndTrust(Properties p, String trustPrefix, 
			String credPrefix, String clientPrefix)
	{
		boolean trustOptional = false, credOptional = false;
		
		String sslP = p.getProperty(clientPrefix + PROP_SSL_ENABLED);
		String sslAuthnP = p.getProperty(clientPrefix + PROP_SSL_AUTHN_ENABLED);
		if (sslP != null && (sslP.equalsIgnoreCase("false") || sslP.equalsIgnoreCase("no")))
			trustOptional = credOptional= true;
		else if (sslAuthnP != null && (sslAuthnP.equalsIgnoreCase("false") || sslAuthnP.equalsIgnoreCase("no")))
			credOptional = true;
		return new AuthnAndTrustProperties(p, trustPrefix, credPrefix, trustOptional, credOptional);
	}
	
	/**
	 * only for cloning
	 */
	protected ClientProperties()
	{
	}
	
	/**
	 * Low level constructor - allow to pass properties, set prefix for client settings 
	 * and a preloaded {@link IAuthnAndTrustConfiguration}
	 * @param p
	 * @param authAndTrust
	 * @throws ConfigurationException
	 */
	public ClientProperties(Properties p, String clientPrefix, IAuthnAndTrustConfiguration authAndTrust) 
			throws ConfigurationException
	{
		setValidator(authAndTrust.getValidator());
		setCredential(authAndTrust.getCredential());
		PropertiesHelper properties = new PropertiesHelper(clientPrefix, p, META, log);
		setSslEnabled(properties.getBooleanValue(PROP_SSL_ENABLED));
		if (isSslEnabled()) 
		{
			setSslAuthn(properties.getBooleanValue(PROP_SSL_AUTHN_ENABLED));
		}
		setDoSignMessage(properties.getBooleanValue(PROP_MESSAGE_SIGNING_ENABLED));
		setHttpAuthn(properties.getBooleanValue(PROP_HTTP_AUTHN_ENABLED));
		if (doHttpAuthn())
		{
			setHttpPassword(properties.getValue(PROP_HTTP_PASSWORD));
			setHttpUser(properties.getValue(PROP_HTTP_USER));
		}
		
		setInHandlerClassNames(parseHandlers(properties, PROP_IN_HANDLERS));
		setOutHandlerClassNames(parseHandlers(properties, PROP_OUT_HANDLERS));
		
		ServerHostnameCheckingMode hostnameMode = properties.getEnumValue(PROP_SERVER_HOSTNAME_CHECKING, ServerHostnameCheckingMode.class);
		setServerHostnameCheckingMode(hostnameMode);
		
		//This is bit tricky: clientPrefix+EXTRA_... is the prefix for extra properties,
		//but EXTRA_... must be left in the keys. 
		String extraPrefix = clientPrefix + EXTRA_HTTP_LIB_PROPERTIES_PREFIX;
		Properties extraSettings = new Properties();
		for (Object k: p.keySet())
		{
			String key = (String)k;
			if (key.startsWith(extraPrefix))
				extraSettings.setProperty(key.substring(
						clientPrefix.length()), p.getProperty(key));
		}
		setExtraSettings(extraSettings);
	}
	
	private String[] parseHandlers(PropertiesHelper properties, String key)
	{
		String handlers = properties.getValue(key);
		if (handlers != null)
			handlers.trim();
		if (handlers != null)
			return handlers.split("[ ]+");
		return new String[0];
	}
	
	@Override
	public ClientProperties clone()
	{
		ClientProperties ret = new ClientProperties();
		super.cloneTo(ret);
		return ret;
	}
}








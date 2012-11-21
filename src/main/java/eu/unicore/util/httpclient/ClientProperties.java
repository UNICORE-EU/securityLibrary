/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import eu.unicore.security.canl.AuthnAndTrustProperties;
import eu.unicore.security.canl.CredentialProperties;
import eu.unicore.security.canl.IAuthnAndTrustConfiguration;
import eu.unicore.security.canl.PasswordCallback;
import eu.unicore.security.canl.TruststoreProperties;
import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.FilePropertiesHelper;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;

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
	private static final Logger log = Log.getLogger(Log.CONFIGURATION, ClientProperties.class);
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
	private static final int DEFAULT_HTTP_TIMEOUT = 20000;
	
	private IAuthnAndTrustConfiguration authnAndTrustConfiguration;
	private PropertiesHelper clientPropertiesHelper;
	

	public final static Map<String, PropertyMD> META = new HashMap<String, PropertyMD>();
	static 
	{
		META.put(PROP_HTTP_AUTHN_ENABLED, new PropertyMD("false").
				setDescription("Whether HTTP basic authentication should be used."));
		META.put(PROP_HTTP_PASSWORD, new PropertyMD("").setSecret().
				setDescription("Password for use with HTTP basic authentication (if enabled)."));
		META.put(PROP_HTTP_USER, new PropertyMD("").
				setDescription("Username for use with HTTP basic authentication (if enabled)."));
		META.put(PROP_IN_HANDLERS, new PropertyMD("").
				setDescription("Space separated list of additional handler class names for handling incoming WS messages"));
		META.put(PROP_MESSAGE_SIGNING_ENABLED, new PropertyMD("true").
				setDescription("Controls whether signing of key web service requests should be performed."));
		META.put(PROP_OUT_HANDLERS, new PropertyMD("").
				setDescription("Space separated list of additional handler class names for handling outgoing WS messages"));
		META.put(PROP_SSL_AUTHN_ENABLED, new PropertyMD("true").
				setDescription("Controls whether SSL authentication of the client should be performed."));
		META.put(PROP_SSL_ENABLED, new PropertyMD("true").
				setDescription("Controls whether the SSL/TLS connection mode is enabled."));
		META.put(PROP_SERVER_HOSTNAME_CHECKING, new PropertyMD(ServerHostnameCheckingMode.WARN).
				setDescription("Controls whether server's hostname should be checked for matching its certificate subject. This verification prevents man-in-the-middle attacks. If enabled WARN will only print warning in log, FAIL will close the connection."));
		META.put(EXTRA_HTTP_LIB_PROPERTIES_PREFIX, new PropertyMD().setCanHaveSubkeys().
				setDescription("Additional settings to be used by the HTTP client. The most useful are '.socket.timeout' and '.connection.timeout'. If those are not set,  default is used: " + DEFAULT_HTTP_TIMEOUT));
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
		this(p, clientPrefix, getDefaultAuthnAndTrust(p, null, trustPrefix, credPrefix, clientPrefix));
	}
	
	public ClientProperties(Properties p, PasswordCallback callback, String trustPrefix, String credPrefix, String clientPrefix) 
			throws ConfigurationException
	{
		this(p, clientPrefix, getDefaultAuthnAndTrust(p, callback, trustPrefix, credPrefix, clientPrefix));
	}
	
	public ClientProperties(Properties p, IAuthnAndTrustConfiguration authAndTrust) 
			throws ConfigurationException
	{
		this(p, DEFAULT_PREFIX, authAndTrust);
	}

	/**
	 * Load cred/validator settings, however assuming that both are optional. The checking if
	 * the required things are configured are done in the main constructor when other client's 
	 * options are evaluated.
	 * @param p
	 * @param trustPrefix
	 * @param credPrefix
	 * @param clientPrefix
	 * @return
	 */
	private static IAuthnAndTrustConfiguration getDefaultAuthnAndTrust(Properties p, PasswordCallback callback, String trustPrefix, 
			String credPrefix, String clientPrefix)
	{
		boolean trustOptional = false, credOptional = false;
		
		String sslP = p.getProperty(clientPrefix + PROP_SSL_ENABLED);
		String sslAuthnP = p.getProperty(clientPrefix + PROP_SSL_AUTHN_ENABLED);
		String signP = p.getProperty(clientPrefix + PROP_MESSAGE_SIGNING_ENABLED);
		//theoretically we can simply set that trust and creds are optional, as anyway it will be strictly verified further.
		//however we perform this trick here, to get detailed error messages - otherwise we would only get
		// "no truststore" or "no keystore"
		if (sslP != null && (sslP.equalsIgnoreCase("false") || sslP.equalsIgnoreCase("no")))
			trustOptional = credOptional= true;
		else if (sslAuthnP != null && (sslAuthnP.equalsIgnoreCase("false") || sslAuthnP.equalsIgnoreCase("no"))
			&& signP != null && (signP.equalsIgnoreCase("false") || signP.equalsIgnoreCase("no")))
			credOptional = true;
		
		return new AuthnAndTrustProperties(p, trustPrefix, credPrefix, callback, trustOptional, credOptional);
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
		this.authnAndTrustConfiguration = authAndTrust;
		clientPropertiesHelper = new PropertiesHelper(clientPrefix, p, META, log);
		setSslEnabled(clientPropertiesHelper.getBooleanValue(PROP_SSL_ENABLED));
		if (isSslEnabled()) 
		{
			if (getValidator() == null)
				throw new ConfigurationException("When SSL mode is enabled " +
						"trust settings must be provided");
			setSslAuthn(clientPropertiesHelper.getBooleanValue(PROP_SSL_AUTHN_ENABLED));
			if (doSSLAuthn() && getCredential() == null)
				throw new ConfigurationException("When SSL authentication is enabled the credential " +
							"must be provided");
			if (getCredential() != null)
				getETDSettings().setIssuerCertificateChain(getCredential().getCertificateChain());
		}
		setDoSignMessage(clientPropertiesHelper.getBooleanValue(PROP_MESSAGE_SIGNING_ENABLED));
		if (doSignMessage() && getCredential() == null)
			throw new ConfigurationException("When message signing is enabled, the credential " +
						"must be provided");
		setHttpAuthn(clientPropertiesHelper.getBooleanValue(PROP_HTTP_AUTHN_ENABLED));
		if (doHttpAuthn())
		{
			setHttpPassword(clientPropertiesHelper.getValue(PROP_HTTP_PASSWORD));
			setHttpUser(clientPropertiesHelper.getValue(PROP_HTTP_USER));
		}
		
		setInHandlerClassNames(parseHandlers(clientPropertiesHelper, PROP_IN_HANDLERS));
		setOutHandlerClassNames(parseHandlers(clientPropertiesHelper, PROP_OUT_HANDLERS));
		
		ServerHostnameCheckingMode hostnameMode = clientPropertiesHelper.getEnumValue(PROP_SERVER_HOSTNAME_CHECKING, 
				ServerHostnameCheckingMode.class);
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
		
		if (!extraSettings.containsKey(HttpUtils.SO_TIMEOUT))
			extraSettings.setProperty(HttpUtils.SO_TIMEOUT, DEFAULT_HTTP_TIMEOUT+"");
		if (!extraSettings.containsKey(HttpUtils.CONNECT_TIMEOUT))
			extraSettings.setProperty(HttpUtils.CONNECT_TIMEOUT, DEFAULT_HTTP_TIMEOUT+"");
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
		ClientProperties ret = (ClientProperties) super.clone();
		ret.authnAndTrustConfiguration = this.authnAndTrustConfiguration.clone();
		ret.clientPropertiesHelper= this.clientPropertiesHelper.clone();
		return ret;
	}

	/**
	 * @return the authnAndTrustConfiguration
	 */
	public IAuthnAndTrustConfiguration getAuthnAndTrustConfiguration()
	{
		return authnAndTrustConfiguration;
	}

	/**
	 * @return the clientPropertiesHelper
	 */
	public PropertiesHelper getClientPropertiesHelper()
	{
		return clientPropertiesHelper;
	}
}








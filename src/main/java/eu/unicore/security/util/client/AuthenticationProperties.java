/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Properties;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.unicore.security.util.ConfigurationException;
import eu.unicore.security.util.CredentialProperties;
import eu.unicore.security.util.FilePropertiesHelper;
import eu.unicore.security.util.LoggingStoreUpdateListener;
import eu.unicore.security.util.TruststoreProperties;


/**
 * Class wrapping all security related settings for a UNICORE client or server:
 * truststore configuration and credentials, configured from a single {@link Properties} source. 
 * Additionally it is possible to retrieve 
 * {@link IAuthenticationConfiguration} implementation, which is the {@link DefaultAuthnConfigurationImpl}
 * based on the truststore and credentials.
 * 
 * @author K. Benedyczak
 */
public class AuthenticationProperties extends DefaultAuthnConfigurationImpl
{
	public AuthenticationProperties(String file) throws IOException, ConfigurationException
	{
		this(new File(file));
	}

	public AuthenticationProperties(File file) throws IOException, ConfigurationException
	{
		this(FilePropertiesHelper.load(file));
	}
	
	public AuthenticationProperties(String file, String trustPrefix, String credPrefix) throws IOException, ConfigurationException
	{
		this(new File(file), trustPrefix, credPrefix);
	}

	public AuthenticationProperties(File file, String trustPrefix, String credPrefix) throws IOException, ConfigurationException
	{
		this(FilePropertiesHelper.load(file), trustPrefix, credPrefix);
	}
	
	public AuthenticationProperties(Properties p) throws ConfigurationException
	{
		this(p, TruststoreProperties.DEFAULT_PREFIX, CredentialProperties.DEFAULT_PREFIX);
	}
	
	public AuthenticationProperties(Properties p, String trustPrefix, String credPrefix) throws ConfigurationException
	{
		super(createValidator(p, trustPrefix),
				new CredentialProperties(p, credPrefix).getCredential());
	}
	
	private static X509CertChainValidator createValidator(Properties p, String trustPrefix)
	{
		TruststoreProperties trustCfg = new TruststoreProperties(p, 
				Collections.singleton(new LoggingStoreUpdateListener()),
				trustPrefix);
		return trustCfg.getValidator();
	}
}

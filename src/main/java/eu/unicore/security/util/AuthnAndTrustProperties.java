/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Properties;



/**
 * Class wrapping all security related settings for a UNICORE client or server:
 * truststore configuration and credentials, configured from a single {@link Properties} source. 
 * 
 * @author K. Benedyczak
 */
public class AuthnAndTrustProperties extends DefaultAuthnAndTrustConfiguration
{
	public AuthnAndTrustProperties(String file) throws IOException, ConfigurationException
	{
		this(new File(file));
	}

	public AuthnAndTrustProperties(File file) throws IOException, ConfigurationException
	{
		this(FilePropertiesHelper.load(file));
	}
	
	public AuthnAndTrustProperties(String file, String trustPrefix, String credPrefix) throws IOException, ConfigurationException
	{
		this(new File(file), trustPrefix, credPrefix);
	}

	public AuthnAndTrustProperties(File file, String trustPrefix, String credPrefix) throws IOException, ConfigurationException
	{
		this(FilePropertiesHelper.load(file), trustPrefix, credPrefix);
	}
	
	public AuthnAndTrustProperties(Properties p) throws ConfigurationException
	{
		this(p, TruststoreProperties.DEFAULT_PREFIX, CredentialProperties.DEFAULT_PREFIX);
	}
	
	public AuthnAndTrustProperties(Properties p, String trustPrefix, String credPrefix) throws ConfigurationException
	{
		TruststoreProperties trustCfg = new TruststoreProperties(p, 
			Collections.singleton(new LoggingStoreUpdateListener()),
			trustPrefix);
		setValidator(trustCfg.getValidator());
		
		CredentialProperties credProps = new CredentialProperties(p, credPrefix); 
		setCredential(credProps.getCredential());
	}
}

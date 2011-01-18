/*
 * Copyright (c) 2010 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 16-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.security.PrivateKey;
import java.util.Properties;

import eu.unicore.security.util.client.SimpleAuthnConfigurationImpl;

/**
 * Do nothing implementation of {@link IClientProperties}.
 * TODO - same as for ICLientPorpoerites. 
 * @author golbi
 *
 */
public class SimpleClientPropertiesImpl extends SimpleAuthnConfigurationImpl 
	implements IClientProperties
{
	private final Properties p = new Properties();
	
	@Override
	public String getOutHandlerClassNames()
	{
		return null;
	}

	@Override
	public String getInHandlerClassNames()
	{
		return null;
	}

	@Override
	public ClassLoader getClassLoader()
	{
		return null;
	}

	@Override
	public boolean isSslEnabled()
	{
		return false;
	}

	@Override
	public Properties getExtraSettings()
	{
		return p;
	}
	
	@Override
	public IClientProperties clone()
	{
		return new SimpleClientPropertiesImpl();
	}

	@Override
	public boolean doSignMessage()
	{
		return false;
	}

	@Override
	public PrivateKey getPrivateKey()
	{
		return null;
	}

	@Override
	public ETDClientSettings getETDSettings()
	{
		return null;
	}
}

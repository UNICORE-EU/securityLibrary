/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

/**
 * Signals a problem with a configuration read from properties.
 * @author K. Benedyczak
 */
public class ConfigurationException extends RuntimeException
{
	private static final long serialVersionUID = 1L;

	public ConfigurationException()
	{
		super();
	}

	public ConfigurationException(String message, Throwable cause)
	{
		super(message, cause);
	}

	public ConfigurationException(String message)
	{
		super(message);
	}
}

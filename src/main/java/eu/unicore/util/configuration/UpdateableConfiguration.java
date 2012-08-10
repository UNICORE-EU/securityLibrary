/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.util.Properties;

/**
 * Implementation provides a method to update its underlying properties.
 * @author K. Benedyczak
 */
public interface UpdateableConfiguration
{
	public void setProperties(Properties newProperties) throws ConfigurationException;
}

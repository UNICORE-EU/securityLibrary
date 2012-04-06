/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;

/**
 * Provides methods to parse properties and return them as ints, longs etc. 
 * Additionally logs when default value is used (INFO) and in case of parsing problems.
 * The class is configured with initial defaults and mandatory properties, so it is easier to call 
 * the 'get' methods.
 * <p> 
 * Can use a custom prefix for properties - such prefix is added for all queried properties, 
 * and therefore acts as a namespace in the configuration file.
 * <p>
 * The class never logs errors: if exception is thrown then logging must be performed by the using class.
 * 
 * @author K. Benedyczak
 */
public class PropertiesHelper
{
	private Set<String> warned = new HashSet<String>();
	protected Logger log;
	protected Properties properties;
	protected String prefix;
	protected Map<String, String> defaults;
	protected Map<String, String> mandatory;
	
	/**
	 * 
	 * @param prefix prefix which is always added to any property being queried
	 * @param properties object with loaded properties to be wrapped
	 * @param defaults map with default values
	 * @param mandatory map with mandatory properties (as keys). Values of the map should 
	 * provide a human readable description of the mandatory property
	 * @param log log object to be used
	 * @throws ConfigurationException if some of the mandatory properties are missing. Exception
	 * message can be presented to the user.
	 */
	public PropertiesHelper(String prefix, Properties properties, Map<String, String> defaults, 
			Map<String, String> mandatory, Logger log) throws ConfigurationException
	{
		this.properties = properties;
		this.prefix = prefix;
		this.log = log;
		this.defaults = defaults;
		if (this.defaults == null)
			this.defaults = Collections.emptyMap();
		this.mandatory = mandatory;
		if (this.mandatory == null)
			this.mandatory = Collections.emptyMap();
		checkMandatoryProperties();
	}

	public synchronized void setProperties(Properties properties) throws IOException, ConfigurationException
	{
		this.properties = properties;
		checkMandatoryProperties();
	}
	
	protected void checkMandatoryProperties() throws ConfigurationException
	{
		StringBuilder builder = new StringBuilder();
		if (mandatory != null)
		{
			for (Map.Entry<String, String> o : mandatory.entrySet())
			{
				if (properties.get(prefix+o.getKey()) == null) 
				{
					String description = o.getValue();
					if (description != null && description.length() > 0)
						builder.append(prefix+o.getKey() + 
							" (" + description + ")").append(" ");
					else
						builder.append(prefix+o.getKey()).append(" ");
				}
			}
		}
		String warns = builder.toString().trim();
		if (warns.length() > 0)
			throw new ConfigurationException("The following mandatory properties are missing" +
					" in the configuration: " + warns);
	}
	
	public String getValue(String name) throws ConfigurationException
	{
		return getValue(name, false);
	}
	
	public String getValue(String name, boolean acceptNoVal) throws ConfigurationException
	{
		String val;
		synchronized(this)
		{
			val = properties.getProperty(prefix + name);
		}
		boolean doLog = !warned.contains(name);
		warned.add(name);
		
		if (doLog)
			log.debug("Parameter " + prefix + name + " value is: " + val);
		if (val == null) 
		{
			String defaultVal = defaults.get(name);
			if (!defaults.containsKey(name) && !acceptNoVal)
				throw new ConfigurationException("No value provided for " + prefix + name);
			if (doLog) 
				log.info("Using default value for " + prefix + name + 
					": " + ((defaultVal == null) ? "--DISABLED--" : defaultVal));
			val = defaultVal;
		}
		return val;
	}

	public long getLongValue(String name) throws ConfigurationException
	{
		return getLongValue(name, false);
	}

	public Long getLongValue(String name, boolean acceptNoVal) throws ConfigurationException
	{
		String val = getValue(name, acceptNoVal);
		if (val == null)
			return null;
		try
		{
			return Long.valueOf(val);
		} catch (NumberFormatException e)
		{
			throw new ConfigurationException("Value " + val + " is not allowed for "
					+ prefix + name + ", must be an integer number");
		}
	}

	public int getIntValue(String name) throws ConfigurationException
	{
		return getIntValue(name, false);
	}
	
	public Integer getIntValue(String name, boolean acceptNoVal) throws ConfigurationException
	{
		String val = getValue(name, acceptNoVal);
		if (val == null)
			return null;
		try
		{
			return Integer.valueOf(val);
		} catch (NumberFormatException e)
		{
			throw new ConfigurationException("Value " + val + " is not allowed for "
					+ prefix + name + ", must be an integer number");
		}
	}

	protected int getIntValue(String name, int min, int max)
	{
		return getIntValue(name, min, max, false);
	}
	
	protected Integer getIntValue(String name, int min, int max, boolean acceptNoVal)
	{
		Integer retVal = getIntValue(name, acceptNoVal);
		
		Integer defaultVal = Integer.parseInt(defaults.get(prefix+name));
		if (retVal < min)
		{
			if (defaultVal != null)
			{
				log.warn(prefix+name + " parameter value "
						+ "is too small, minimum is " + min 
						+ ", using default: " + defaultVal);
				return defaultVal;
			} else
			{
				throw new ConfigurationException(prefix+name + " parameter value "
						+ "is too small, minimum is " + min);
			}
		}
		if (retVal > max)
		{
			if (defaultVal != null)
			{
				log.warn(prefix+name + " parameter value "
						+ "is too bog, maximum is " + max 
						+ ", using default: " + defaultVal);
				return defaultVal;
			} else
			{
				throw new ConfigurationException(prefix+name + " parameter value "
						+ "is too big, maximum is " + max);
			}
		}
		return retVal;
	}


	public boolean getBooleanValue(String name) throws ConfigurationException
	{
		return getBooleanValue(name, false);
	}
	
	public Boolean getBooleanValue(String name, boolean acceptNoVal) throws ConfigurationException
	{
		String val = getValue(name, acceptNoVal);
		if (val == null)
			return null;
        	if (val.equalsIgnoreCase("true") || val.equalsIgnoreCase("yes"))
        		return true;
        	if (val.equalsIgnoreCase("false") || val.equalsIgnoreCase("no"))
        		return false;
		throw new ConfigurationException("Value " + val + " is not allowed for "
				+ prefix + name + ", must be one of yes|true|no|false");
	} 
}






/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.log4j.Logger;

/**
 * Provides methods to parse properties and return them as String, ints, longs, Files or Lists of strings. 
 * Logs values read from Properties source, additionally logs when default value is used (on DEBUG level) 
 * and in case when out of range values are found and defaults are present and used instead (WARN). 
 * The logging is performed only once per property. The object is configured with initial defaults and mandatory 
 * properties, so it is easier to call the 'get' methods later.
 * <p> 
 * The class can use a custom prefix for properties - such prefix is added for all queried properties, 
 * and therefore acts as a namespace in the configuration file.
 * <p>
 * The class never logs errors: if exception is thrown then logging must be performed by the using class.
 * 
 * @author K. Benedyczak
 */
public class PropertiesHelper
{
	private Set<String> warned = Collections.synchronizedSet(new HashSet<String>());
	protected Logger log;
	protected Properties properties;
	protected String prefix;
	protected Map<String, PropertyMD> metadata;
	
	/**
	 * 
	 * @param prefix prefix which is always added to any property being queried
	 * @param properties object with loaded properties to be wrapped
	 * @param propertiesMD metadata about properties
	 * @param log log object to be used
	 * @throws ConfigurationException if some of the mandatory properties are missing. Exception
	 * message can be presented to the user.
	 */
	public PropertiesHelper(String prefix, Properties properties, Map<String, PropertyMD> propertiesMD, 
			Logger log) throws ConfigurationException
	{
		this.properties = properties;
		this.prefix = prefix;
		this.log = log;
		this.metadata = propertiesMD;
		if (this.metadata == null)
			this.metadata = Collections.emptyMap();
		checkMandatoryProperties(properties);
	}

	public synchronized void setProperties(Properties properties) throws IOException, ConfigurationException
	{
		checkMandatoryProperties(properties);
		this.properties = properties;
	}
	
	protected void checkMandatoryProperties(Properties properties) throws ConfigurationException
	{
		StringBuilder builder = new StringBuilder();
		for (Map.Entry<String, PropertyMD> o : metadata.entrySet())
		{
			if (o.getValue().isMandatory() && properties.get(prefix+o.getKey()) == null) 
			{
				String description = o.getValue().getDescription();
				if (description != null && description.length() > 0)
					builder.append(prefix+o.getKey() + 
						" (" + description + ")").append(" ");
				else
					builder.append(prefix+o.getKey()).append(" ");
			}
		}
		String warns = builder.toString().trim();
		if (warns.length() > 0)
			throw new ConfigurationException("The following mandatory properties are missing" +
					" in the configuration: " + warns);
	}
	
	public String getValue(String name)
	{
		String val;
		synchronized(this)
		{
			val = properties.getProperty(prefix + name);
		}
		boolean doLog = (!warned.contains(name));
		
		if (doLog) 
			logValue(name, val);

		if (val == null) 
		{
			PropertyMD meta = metadata.get(name);
			boolean hasDefault = meta != null ? meta.hasDefault() : false;
			if (hasDefault)
			{
				String defaultVal = meta.getDefault();
				if (doLog) 
					log.debug("Using default value for " + prefix + name + ": " + 
						((defaultVal == null) ? "--BY DEFAULT NOT SET--" : defaultVal));
				val = defaultVal;
			}
		}
		return val;
	}

	protected Long getLongValueNoCheck(String name) throws ConfigurationException
	{
		String val = getValue(name);
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

	protected Integer getIntValueNoCheck(String name) throws ConfigurationException
	{
		String val = getValue(name);
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

	protected <T extends Number> T checkBounds(String name, T current) throws ConfigurationException
	{
		PropertyMD meta = metadata.get(prefix+name);
		if (meta == null)
			return current;
		if (current.longValue() < meta.getMin())
		{
			throw new ConfigurationException(prefix+name + " parameter value "
					+ "is too small, minimum is " + meta.getMin());
		}
		if (current.longValue() > meta.getMax())
		{
			throw new ConfigurationException(prefix+name + " parameter value "
					+ "is too big, maximum is " + meta.getMax());
		}
		
		return current;
	}
	
	public Long getLongValue(String name) throws ConfigurationException
	{
		Long retVal = getLongValueNoCheck(name);
		return checkBounds(name, retVal);
	}	
	
	public Integer getIntValue(String name) throws ConfigurationException
	{
		Integer retVal = getIntValueNoCheck(name);
		return checkBounds(name, retVal);
	}


	public Boolean getBooleanValue(String name) throws ConfigurationException
	{
		String val = getValue(name);
		if (val == null)
			return null;
        	if (val.equalsIgnoreCase("true") || val.equalsIgnoreCase("yes"))
        		return true;
        	if (val.equalsIgnoreCase("false") || val.equalsIgnoreCase("no"))
        		return false;
		throw new ConfigurationException("Value " + val + " is not allowed for "
				+ prefix + name + ", must be one of yes|true|no|false");
	}

	
	/**
	 * See {@link #getFileValue(String, boolean, boolean)}. This version converts the result
	 * to String, handling nulls.
	 */
	public String getFileValueAsString(String name, boolean isDirectory) 
			throws ConfigurationException
	{
		File f = getFileValue(name, isDirectory);
		if (f == null)
			return null;
		return f.toString();
	}
	/**
	 * Returns a property value interpreted as a {@link File}. 
	 * The file must exist and must be readable.
	 * @param name
	 * @param isDirectory whether the File must be a directory (true) or a plain file (false)
	 * @return
	 * @throws ConfigurationException
	 */
	public File getFileValue(String name, boolean isDirectory) 
			throws ConfigurationException
	{
		String val = getValue(name);
		if (val == null)
			return null;
			
		File f = new File(val);
		
		if (!f.exists() || !f.canRead())
			throw new ConfigurationException("The value of "
					+ prefix + name + "= '" + val + 
					"', must represent an EXISTING and READABLE filesystem path.");
		if (!f.isDirectory() && isDirectory)
			throw new ConfigurationException("Value of "
					+ prefix + name + "= '" + val +
					"', must be a path of a directory, not a file.");
		if (!f.isFile() && !isDirectory)
			throw new ConfigurationException("Value of "
					+ prefix + name + "= '" + val +
					"', must be a path of an ordinary file.");
		return f;
	}

	
	/**
	 * Returns a sorted list of values. Each value corresponds to a property
	 * with a key with a specified prefix and arbitrary ending. Usually this prefix should end with '.'
	 * (it is not added automatically). 
	 * <p>
	 * Example, for:
	 * <pre>
	 * generalPrefix.ourListProperty.2=val2
	 * generalPrefix.ourListProperty.1=val1
	 * </pre>
	 * will result in (val1, val2) if invoked with 'ourListProperty.' as argument.
	 *   
	 * @param prefix2 the prefix to be used.
	 * @param numericalKeys whether to use only integer keys, sorted numerically. 
	 * Keys which are not numbers are skipped with a warning. 
	 * If false, sorting is lexical and all keys are used. 
	 * @return
	 */
	public synchronized List<String> getListOfValues(String prefix2, boolean numericalKeys)
	{
		String base = prefix + prefix2;
		Set<String> keys = numericalKeys ? getSortedNumKeys(base) : getSortedStringKeys(base);
		
		List<String> ret = new ArrayList<String>();
		for (Object keyO: keys)
		{
			String key = keyO.toString();
			String v = properties.getProperty(key);
			if (!warned.contains(key))
				logValue(key.substring(prefix.length()), v);
			ret.add(v);
		}
		return ret;
	}
	
	private synchronized Set<String> getSortedNumKeys(String base)
	{
		SortedSet<Integer> keys = new TreeSet<Integer>();
		Set<Object> allKeys = properties.keySet();
		for (Object keyO: allKeys)
		{
			String key = (String) keyO;
			if (key.startsWith(base))
			{
				String post = key.substring(base.length());
				try
				{
					int i = Integer.parseInt(post);
					keys.add(i);
				} catch (NumberFormatException e)
				{
					log.warn("Property list key '" + key + 
						"' should end with integer number, but is ended with '" +
						post + "'. Ignoring.");
				}
			}
		}
		
		Set<String> ret = new LinkedHashSet<String>(keys.size());
		for (Integer suffix: keys)
			ret.add(base+suffix);
		
		return ret;
	}

	private synchronized Set<String> getSortedStringKeys(String base)
	{
		SortedSet<String> keys = new TreeSet<String>();
		Set<Object> allKeys = properties.keySet();
		for (Object keyO: allKeys)
		{
			String key = (String) keyO;
			if (key.startsWith(base))
				keys.add(key);
		}
		return keys;
	}
	
	protected void logValue(String name, String val) 
	{
		warned.add(name);
		PropertyMD meta = metadata.get(name);
		boolean hideValue = false;
		if (meta != null && meta.isSecret())
			hideValue = true;
			
		if (val == null)
			log.debug("Parameter " + prefix + name + " value is not set");
		else
			log.debug("Parameter " + prefix + name + " value is: " + 
				(hideValue ? "--SECRET--" : val));
	}
	
	public synchronized boolean isSet(String name)
	{
		return properties.containsKey(prefix+name);
	}
	
	public synchronized void setProperty(String key, String value)
	{
		//value == null can not be set
		if (value == null)
		{
			PropertyMD meta = metadata.get(key);
			if (meta != null && meta.isMandatory())
				throw new IllegalArgumentException("Can not remove a mandatory property");
			properties.remove(prefix+key);
		} else
			properties.setProperty(prefix+key, value);
		warned.remove(key);
	}
}






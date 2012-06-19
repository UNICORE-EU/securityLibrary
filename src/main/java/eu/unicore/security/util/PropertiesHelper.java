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
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.log4j.Logger;

import eu.unicore.security.util.PropertyMD.Type;

/**
 * Provides methods to parse properties and return them as String, ints, longs, Files, arbitrary Enums 
 * or Lists of strings. 
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
		checkConstraints(properties);
		findUnknown();
	}

	public synchronized void setProperties(Properties properties) throws IOException, ConfigurationException
	{
		checkConstraints(properties);
		this.properties = properties;
	}
	
	protected void checkConstraints(Properties properties) throws ConfigurationException
	{
		StringBuilder builder = new StringBuilder();
		
		for (Map.Entry<String, PropertyMD> o : metadata.entrySet())
		{
			PropertyMD meta = o.getValue();
			try 
			{
				checkPropertyConstraints(meta, o.getKey());
			} catch (ConfigurationException e)
			{
				builder.append(e.getMessage() + "\n");
			}
		}
		String warns = builder.toString().trim();
		if (warns.length() > 0)
			throw new ConfigurationException("The following problems were found in the configuration:\n"
					+ warns);
	}
	
	protected void checkPropertyConstraints(PropertyMD meta, String key) throws ConfigurationException {
		if (meta.isMandatory() && !isSet(key)) 
			throw new ConfigurationException("The property " + getKeyDescription(key) + 
					" is mandatory");
		
		String value = properties.getProperty(prefix + key);
		if (value == null && meta.getType() != Type.LIST)
			return;
		switch (meta.getType()) 
		{
		case PATH:
			try
			{
				new File(value).getCanonicalPath();
			} catch (IOException e1)
			{
				throw new ConfigurationException("The property" + getKeyDescription(key) + 
						" must be a filesystem path, but is not: " + e1.getMessage());
			}
			break;
		case INT:
			getIntValue(key);
			break;
		case LONG:
			getLongValue(key);
			break;
		case BOOLEAN:
			getBooleanValue(key);
			break;
		case ENUM:
			getEnumValue(key, meta.getEnumTypeInstance().getDeclaringClass());
			break;
		case LIST:
			if (meta.numericalListKeys())
			{
				Set<String> listKeys = getSortedStringKeys(prefix+key);
				int l = (prefix+key).length();
				for (String k: listKeys)
				{
					try
					{
						Integer.parseInt(k.substring(l));
					} catch (NumberFormatException e)
					{
						throw new ConfigurationException("For the " + prefix + key + 
								" list property only the numerical subkeys are allowed, and " + k + " doesn't end with a numerical value.");
					}
				}
			}
			break;
		}
	}
	
	protected void findUnknown()
	{
		Set<Object> keys = properties.keySet();
		StringBuilder sb = new StringBuilder();
		for (Object keyO: keys)
		{
			String key = (String) keyO;
			if (key.startsWith(prefix))
			{
				String noPfxKey = key.substring(prefix.length());
				if (getMetadata(noPfxKey) == null)
					sb.append(" ").append(key);
			}
		}
		if (sb.length() > 0)
			throw new ConfigurationException("The following properties are not known:" + sb.toString() + 
					". Remove them or use correct property names if there are mistakes.");
	}
	
	protected PropertyMD getMetadata(String key)
	{
		if (metadata.containsKey(key))
			return metadata.get(key);
		
		Set<Entry<String, PropertyMD>> entries = metadata.entrySet();
		for (Entry<String, PropertyMD> entry: entries)
		{
			if (key.startsWith(entry.getKey()) && 
					(entry.getValue().getType() == Type.LIST || entry.getValue().canHaveSubkeys()))
				return entry.getValue();
		}
		return null;
	}

	/**
	 * 
	 * @param key
	 * @return string with a full name of the key and its description if set.
	 */
	public String getKeyDescription(String key) 
	{
		PropertyMD meta = metadata.get(key);
		if (meta == null)
			return prefix + key;
		
		String description = meta.getDescription();
		if (description != null && description.length() > 0)
			return prefix + key + " (" + description + ")";
		else
			return prefix + key;
	}
	
	public String getValue(String name)
	{
		String val;
		synchronized(this)
		{
			val = properties.getProperty(prefix + name);
		}
		boolean doLog = (!warned.contains(name));
		
		if (val == null) 
		{
			PropertyMD meta = metadata.get(name);
			boolean hasDefault = meta != null ? meta.hasDefault() : false;
			if (hasDefault)
			{
				String defaultVal = meta.getDefault();
				if (doLog)
				{
					log.debug("Parameter " + getKeyDescription(name) + " value is not set, using default value: " +
						((defaultVal == null) ? "--BY DEFAULT NOT SET--" : defaultVal));
					warned.add(name);
				}
				val = defaultVal;
			}
		} else
		{
			if (doLog) 
				logValue(name, val);
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
					+ getKeyDescription(name) + ", must be an integer number");
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
					+ getKeyDescription(name) + ", must be an integer number");
		}
	}

	protected <T extends Number> T checkBounds(String name, T current) throws ConfigurationException
	{
		if (current == null)
			return current;
		PropertyMD meta = metadata.get(name);
		if (meta == null)
			return current;
		if (current.longValue() < meta.getMin())
		{
			throw new ConfigurationException(getKeyDescription(name) + " parameter value "
					+ "is too small, minimum is " + meta.getMin());
		}
		if (current.longValue() > meta.getMax())
		{
			throw new ConfigurationException(getKeyDescription(name) + " parameter value "
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
				+ getKeyDescription(name) + ", must be one of yes|true|no|false");
	}

	/**
	 * Returns the value of name key as a provided enum class instance. Important: mapping of string
	 * value to enum label is done in case insensitive way. Therefore if your enum constants differ
	 * only in case, do not use this method.
	 * @param name
	 * @param type
	 * @return
	 * @throws ConfigurationException
	 */
	public <T extends Enum<T>> T getEnumValue(String name, Class<T> type) throws ConfigurationException
	{
		String val = getValue(name);
		if (val == null)
			return null;
		T[] constants = type.getEnumConstants();
		StringBuilder allowed = new StringBuilder();
		for (T label: constants) 
		{
			if (val.equalsIgnoreCase(label.name()))
				return label;
			allowed.append(label.name() + " ");
		}
		throw new ConfigurationException("Value " + val + " is not allowed for "
				+ getKeyDescription(name) + ", must be one of " + allowed);
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
					+ getKeyDescription(name) + "= '" + val + 
					"', must represent an EXISTING and READABLE filesystem path.");
		if (!f.isDirectory() && isDirectory)
			throw new ConfigurationException("Value of "
					+ getKeyDescription(name) + "= '" + val +
					"', must be a path of a directory, not a file.");
		if (!f.isFile() && !isDirectory)
			throw new ConfigurationException("Value of "
					+ getKeyDescription(name) + "= '" + val +
					"', must be a path of an ordinary file.");
		return f;
	}

	/**
	 * Gets a property that can be defined with a subkey.<br/> 
	 * As primary fallback, gets the "general" property. 
	 * Thus, the lookup sequence to find the property is:
	 * <ul>
	 * <li>key.subkey</li>
	 * <li>key</li>
	 * <li>key's default value</li>
	 * </ul>
	 * 
	 * @param key the property key
	 * @param subKey the sub key
	 * @return property value or null if not set and there is no default
	 */
	public String getSubkeyValue(String key, String subKey) {
		String perServiceKey = key + "." + subKey; 
		if (isSet(perServiceKey))
			return getValue(perServiceKey);
		return getValue(key);
	}

	/**
	 * @see #getSubkeyValue(String, String)
	 * @param key
	 * @param subKey
	 * @return
	 */
	public Boolean getSubkeyBooleanValue(String key, String subKey) {
		String perServiceKey = key + "." + subKey; 
		if (isSet(perServiceKey))
			return getBooleanValue(perServiceKey);
		return getBooleanValue(key);
	}

	/**
	 * @see #getSubkeyValue(String, String)
	 * @param key
	 * @param subKey
	 * @return
	 */
	public Integer getSubkeyIntValue(String key, String subKey) {
		String perServiceKey = key + "." + subKey; 
		if (isSet(perServiceKey))
			return getIntValue(perServiceKey);
		return getIntValue(key);
	}
	
	/**
	 * @see #getSubkeyValue(String, String)
	 * @param key
	 * @param subKey
	 * @return
	 */
	public Long getSubkeyLongValue(String key, String subKey) {
		String perServiceKey = key + "." + subKey; 
		if (isSet(perServiceKey))
			return getLongValue(perServiceKey);
		return getLongValue(key);
	}
	
	/**
	 * @see #getSubkeyValue(String, String)
	 * @param key
	 * @param subKey
	 * @return
	 */
	public <T extends Enum<T>> T getSubkeyEnumValue(String key, String subKey, Class<T> type) {
		String perServiceKey = key + "." + subKey; 
		if (isSet(perServiceKey))
			return getEnumValue(perServiceKey, type);
		return getEnumValue(key, type);
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
	 * <p>
	 * property metadata defines whether list sub keys should be restricted to numerical values only.
	 * If so list keys are sorted as numbers and keys which are not numbers are skipped with warning.  
	 * @param prefix2 the prefix to be used.
	 * @return
	 */
	public synchronized List<String> getListOfValues(String prefix2)
	{
		String base = prefix + prefix2;
		PropertyMD meta = metadata.get(prefix2);
		boolean numericalKeys = meta == null ? false : meta.numericalListKeys();
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
			log.debug("Parameter " + getKeyDescription(name) + " value is not set");
		else
			log.debug("Parameter " + getKeyDescription(name) + " value is: " + 
				(hideValue ? "--SECRET--" : val));
	}
	
	public synchronized boolean isSet(String name)
	{
		return properties.containsKey(prefix+name);
	}
	
	public synchronized void setProperty(String key, String value)
	{
		PropertyMD meta = metadata.get(key);
		//value == null can not be set
		if (value == null)
		{
			if (meta != null && meta.isMandatory())
				throw new IllegalArgumentException("Can not remove a mandatory property");
			properties.remove(prefix+key);
		} else
		{
			if (meta != null)
				checkPropertyConstraints(meta, key);
			properties.setProperty(prefix+key, value);
		}
		warned.remove(key);
	}
	
	/**
	 * @param key a full key
	 * @return value of a raw property, i.e. without any metadata checking, usage of prefix etc.
	 */
	public synchronized String getRawProperty(String key)
	{
		return properties.getProperty(key);
	}
}






/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.log4j.Logger;

import eu.unicore.util.configuration.PropertyMD.Type;
import eu.unicore.util.jetty.HttpServerProperties;

/**
 * Provides methods to parse properties and return them as String, ints, longs, Files, arbitrary Enums 
 * or Lists of strings or others. There is a number of additional features provided.
 * <p> 
 * The object is configured with metadata about properties, so it is easier to call the 'get' methods later.
 * Metadata provides the following features: (1) ability to generate documentation with properties reference,
 * (2) provides default values for not set properties and (3) can define types and permitted values.
 * Note that metadata is used when the object is created or when underlying properties are modified. During the 
 * retrieval you can trick the system and for instance try to get a value of "INT" property as a String or 
 * even File. However this is strongly not suggested - typically you should use the get***Value() method
 * corresponding to the property type. If you do so you can be sure that no exception is raised. If you 
 * try to change the type at runtime you have no such guarantee. 
 * <p>
 * The object maintains a private copy of properties passed as constructor argument. All modifications of the
 * source properties must be signaled using {@link #setProperty(String, String)} or 
 * {@link #setProperties(Properties)} methods. 
 * <p>
 * The class logs values read from Properties source, additionally logs when default value is used (on DEBUG level). 
 * The logging is performed only once per property. 
 * The class never logs errors: if exception is thrown then logging must be performed by the using class.
 * <p> 
 * The class can use a custom prefix for properties - such prefix is added for all queried properties, 
 * and therefore acts as a namespace in the configuration file. The class also checks for unknown properties 
 * (i.e. the ones which doesn't have a metadata attached) so it is important to stick to the convention:
 * dot in property name should be used exclusively to separate (sub)namespace.    
 * <p>
 * It is possible to register for property changes. The implementation is smart, i.e. it allows for detecting changes
 * of particular properties or changes in property groups if a listener is registered for a property which can 
 * have subkeys.
 * <p>
 * This class can be used in two ways: either as a helper class of a high-level configuration class,
 * which provides a custom interface to obtaining configuration data (e.g. {@link ClientProperties})
 * or can be extended if the interface of this class is enough (as in the case of {@link HttpServerProperties}. 
 * The first solution is suggested when there are
 * many complicated interconnections between properties or if high level objects should be returned for convenience.
 * <p>
 * If this class is extended, then the extending class should take care to properly check for its custom constraints,
 * by overriding {@link #checkPropertyConstraints(Properties, PropertyMD, String)} method (not forgetting to call
 * super). 
 * <p>
 * This class is thread safe.
 * 
 * @author K. Benedyczak
 */
public class PropertiesHelper implements Cloneable, UpdateableConfiguration
{
	private Set<String> warned = Collections.synchronizedSet(new HashSet<String>());
	protected Logger log;
	protected Properties properties;
	protected String prefix;
	protected Map<String, PropertyMD> metadata;
	protected List<PropertyChangeListener> genericListeners = new ArrayList<PropertyChangeListener>();
	protected Map<String, List<PropertyChangeListener>> propertyFocusedListeners = 
			new HashMap<String, List<PropertyChangeListener>>(); 
	protected Set<String> structuredPrefixes = new HashSet<String>();
	
	
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
		this.properties = new Properties();
		this.properties.putAll(properties);
		this.prefix = prefix;
		this.log = log;
		this.metadata = propertiesMD;
		if (this.metadata == null)
			this.metadata = Collections.emptyMap();
		checkConstraints();
		findUnknown(properties);
	}

	public synchronized void setProperties(Properties properties) throws ConfigurationException
	{
		checkConstraints(properties);
		findUnknown(properties);
		Set<String> changed = filterChanged(propertyFocusedListeners.keySet(), this.properties, properties);
		this.properties.clear();
		this.properties.putAll(properties);
		notifyGenericListeners();
		for (String changedP: changed)
			notifyFocusedListeners(changedP);
	}

	public synchronized void setProperty(String key, String value)
	{
		Properties tmp = new Properties();
		tmp.putAll(properties);
		
		boolean change;
		//value == null can not be set
		if (value == null)
		{
			change = tmp.remove(prefix+key) != null;
		} else
		{
			change = !value.equals(properties.getProperty(prefix+key));
			tmp.setProperty(prefix+key, value);
		}
		checkConstraints(tmp);
		
		properties = tmp;
		warned.remove(key);
		notifyGenericListeners();
		if (change)
			notifyFocusedListeners(key);
	}

	private boolean canHaveSubkeys(String key) 
	{
		PropertyMD meta = getMetadata(key);
		if (meta != null && (meta.canHaveSubkeys() || meta.getType() == Type.LIST) || 
				meta.getType() == Type.STRUCTURED_LIST)
			return true;
		return false;
	}
	
	protected Set<String> filterChanged(Set<String> toCheck, Properties orig, Properties updated)
	{
		Set<String> ret = new HashSet<String>();
		for (String p: toCheck)
		{
			boolean group = canHaveSubkeys(p);
			
			if (!group)
			{
				String origVal = orig.getProperty(prefix+p);
				String updatedVal = updated.getProperty(prefix+p);
				if (origVal == null || updatedVal == null) 
				{
					if (origVal != updatedVal)
						ret.add(p);
				} else
				{
					if (!origVal.equals(updatedVal))
						ret.add(p);
				}
			} else
			{ //for properties with subkeys we check if any of the properties in the group changed
				Map<String, String> origGroup = new PropertyGroupHelper(orig, prefix+p).getFilteredMap();
				Map<String, String> updatedGroup = new PropertyGroupHelper(updated, prefix+p).getFilteredMap();
				if (!origGroup.equals(updatedGroup))
					ret.add(p);
			}
		}
		return ret;
	}
	
	protected void notifyFocusedListeners(String property)
	{
		synchronized(genericListeners)
		{
			//we have to handle differently the listeners which listen to updates of properties with subkeys
			for (String key: propertyFocusedListeners.keySet())
			{
				if (key.equals(property))
				{
					notifyAllWithKey(key, property);
				} else if (property.startsWith(key) && canHaveSubkeys(key))
				{
					notifyAllWithKey(key, property);
				}
			}
		}		
	}

	protected void notifyAllWithKey(String key, String property)
	{
		List<PropertyChangeListener> listeners = propertyFocusedListeners.get(key);
		for (PropertyChangeListener listener: listeners)
			listener.propertyChanged(property);
	}
	
	protected void notifyGenericListeners()
	{
		synchronized(genericListeners)
		{
			for (PropertyChangeListener listener: genericListeners)
				listener.propertyChanged(null);
		}		
	}
	
	public void addPropertyChangeListener(PropertyChangeListener listener) 
	{
		synchronized(genericListeners)
		{
			if (listener.getInterestingProperties() == null)
				genericListeners.add(listener);
			else
			{
				String[] interestingProps = listener.getInterestingProperties();
				for (String prop: interestingProps)
				{
					List<PropertyChangeListener> propListeners = propertyFocusedListeners.get(prop);
					if (propListeners == null) 
					{
						propListeners = new ArrayList<PropertyChangeListener>();
						propertyFocusedListeners.put(prop, propListeners);
					}
					propListeners.add(listener);
				}
			}
		}
	}
	
	public void removePropertyChangeListener(PropertyChangeListener listener)
	{
		synchronized(genericListeners)
		{
			genericListeners.remove(listener);
			for (String key: propertyFocusedListeners.keySet())
				propertyFocusedListeners.get(key).remove(listener);
		}
	}
	
	/**
	 * Checks if new properties are correct.
	 * @param properties properties to be checked.
	 * @throws ConfigurationException
	 */
	protected void checkConstraints(Properties properties) throws ConfigurationException
	{
		//tricky but short
		new PropertiesHelper(prefix, properties, metadata, log);
	}
	
	/**
	 * Checks if the properties set to this object are correct.
	 * @throws ConfigurationException
	 */
	protected void checkConstraints() throws ConfigurationException
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
		//we check structured members only when called specially in recursive way
		if (meta.isStructuredListEntry() && !key.startsWith(meta.getStructuredListEntryId()))
			return;
		
		if (meta.isMandatory() && !isSet(key) && !(meta.getType() == Type.LIST || 
				meta.getType() == Type.STRUCTURED_LIST || meta.canHaveSubkeys())) 
			throw new ConfigurationException("The property " + getKeyDescription(key) + 
					" is mandatory");
		
		String value = getValue(key);
		if (value == null && meta.getType() != Type.LIST && meta.getType() != Type.STRUCTURED_LIST)
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
		case FLOAT:
			
			break;
		case BOOLEAN:
			getBooleanValue(key);
			break;
		case ENUM:
			getEnumValue(key, meta.getEnumTypeInstance().getDeclaringClass());
			break;
		case LIST:
			Set<String> listKeys = getSortedStringKeys(prefix+key, false);
			if (meta.isMandatory() && listKeys.size() == 0)
				throw new ConfigurationException("The property " + getKeyDescription(key) + 
						" is mandatory");
			if (meta.numericalListKeys())
			{
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
		case CLASS:
			getClassValue(key, meta.getBaseClass());
		case STRING:
			break;
		case STRUCTURED_LIST:
			checkStructuredListConstraints(meta, key);
			break;
		}
	}

	private void checkStructuredListConstraints(PropertyMD meta, String key) 
	{
		structuredPrefixes.add(key);
		if (meta.numericalListKeys())
		{
			Set<String> listKeys2 = getSortedStringKeys(prefix+key, true);
			int l = (prefix+key).length();
			for (String k: listKeys2)
			{
				k = k.substring(l);
				try
				{
					Integer.parseInt(k);
				} catch (NumberFormatException e)
				{
					throw new ConfigurationException("For the " + prefix + key + 
						" structurd list property only the numerical subkeys are allowed, and " + k + " isn't a numerical subkey.");
				}
			}
		}
		
		Set<String> mandatoryElements = new HashSet<String>();
		for (Map.Entry<String, PropertyMD> o : metadata.entrySet())
		{
			PropertyMD m = o.getValue();
			if (m.isStructuredListEntry() && key.equals(m.getStructuredListEntryId()) && m.isMandatory())
				mandatoryElements.add(o.getKey());
		}
		
		Set<String> elements = getStructuredListKeys(key);
		if (meta.isMandatory() && elements.size() == 0)
			throw new ConfigurationException("The list " + getKeyDescription(key) + 
					" must have elements");
		for (String element: elements)
		{
			Set<String> presentMandatory = new HashSet<String>();
			PropertyGroupHelper helper = new PropertyGroupHelper(properties, prefix+element);
			Iterator<String> keys = helper.keys();
			while(keys.hasNext())
			{
				String entryKey = keys.next();
				entryKey = entryKey.substring(prefix.length());
				PropertyMD eMeta = getMetadata(entryKey);
				if (eMeta != null)
				{
					String realKey = getMetadataKey(entryKey);
					if ((eMeta.canHaveSubkeys() || eMeta.getType() == Type.LIST) && entryKey.endsWith(realKey))
						throw new ConfigurationException("The entry with key " + prefix+entryKey + " is illegal, should have a subkey");
					if (eMeta.canHaveSubkeys() || eMeta.getType() == Type.LIST)
						entryKey = entryKey.substring(0, entryKey.indexOf(realKey))+realKey;
					checkPropertyConstraints(eMeta, entryKey);
					if (eMeta.isMandatory())
						presentMandatory.add(realKey);
				}
			}
			if (!mandatoryElements.equals(presentMandatory))
			{
				mandatoryElements.removeAll(presentMandatory);
				throw new ConfigurationException("The following properties must be defined for the list entry with key " 
						+ element + ": " + mandatoryElements);
			}
		}
	}
	
	
	protected void findUnknown(Properties properties)
	{
		Set<Object> keys = properties.keySet();
		StringBuilder sb = new StringBuilder();
		for (Object keyO: keys)
		{
			String key = (String) keyO;
			if (key.startsWith(prefix))
			{
				String noPfxKey = key.substring(prefix.length());
				if (getMetadata(noPfxKey) != null)
					continue;
				//let's also try if we have metadata for some subnamespaces, marked as list or with subkeys.
				boolean done = false;
				while (noPfxKey.contains(".")) {
					noPfxKey = noPfxKey.substring(0, noPfxKey.lastIndexOf('.'));
					PropertyMD md = getMetadata(noPfxKey); 
					if (md != null) {
						if (!md.canHaveSubkeys() && md.getType() != Type.LIST) {
							sb.append(" ").append(key);
						}
						done = true;
						break;
					}
				}
				if (!done)
					sb.append(" ").append(key);
			}
		}
		if (sb.length() > 0)
			throw new ConfigurationException("The following properties are not known:" + sb.toString() + 
					". Remove them or use correct property names if there are mistakes.");
	}
	
	/**
	 * For regular entries returns the argument. For entries where propertyKey is something from a list 
	 * or entry with subkeys, the real entry key is returned. Similarily for the structured list - the structured
	 * list entry is returned. 
	 * 
	 * @param propertyKey
	 * @return
	 */
	protected String getMetadataKey(String propertyKey)
	{
		if (metadata.containsKey(propertyKey))
			return propertyKey;
		
		String realKey = propertyKey;
		for (String structuredPrefix: structuredPrefixes)
		{
			if (propertyKey.startsWith(structuredPrefix))
			{
				realKey = propertyKey.substring(structuredPrefix.length());
				int dot = realKey.indexOf('.');
				realKey = realKey.substring(dot+1);
				PropertyMD md = metadata.get(realKey);
				if (md != null)
					return realKey;
				break; //maybe this is a list or something with subkeys, in the structured list
			}
		}
		
		Set<Entry<String, PropertyMD>> entries = metadata.entrySet();
		for (Entry<String, PropertyMD> entry: entries)
		{
			if (realKey.startsWith(entry.getKey()) && 
					(entry.getValue().getType() == Type.LIST || entry.getValue().canHaveSubkeys()))
				return entry.getKey();
		}
		return null;
		
	}
	
	protected PropertyMD getMetadata(String key)
	{
		String realKey = getMetadataKey(key);
		return realKey == null ? null: metadata.get(realKey);
	}

	/**
	 * 
	 * @param key
	 * @return string with a full name of the key and its description if set.
	 */
	public String getKeyDescription(String key) 
	{
		PropertyMD meta = getMetadata(key);
		if (meta == null)
			return prefix + key;
		
		String description = meta.getDescription();
		if (description != null && description.length() > 0) {
			String shortDesc = description.length() < 40 ? description : description.substring(0, 37)+"...";
			return prefix + key + " (" + shortDesc + ")";
		} else
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
			PropertyMD meta = getMetadata(name);
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
			val=val.trim();
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

	protected Double getDoubleValueNoCheck(String name) throws ConfigurationException
	{
		String val = getValue(name);
		if (val == null)
			return null;
		try
		{
			return Double.valueOf(val);
		} catch (NumberFormatException e)
		{
			throw new ConfigurationException("Value " + val + " is not allowed for "
					+ getKeyDescription(name) + ", must be a floating point (rational) number");
		}
	}

	protected <T extends Number> T checkBounds(String name, T current) throws ConfigurationException
	{
		if (current == null)
			return current;
		PropertyMD meta = getMetadata(name);
		if (meta == null)
			return current;
		if (current instanceof Float || current instanceof Double)
		{
			if (current.doubleValue() < meta.getMinFloat())
			{
				throw new ConfigurationException(getKeyDescription(name) + " parameter value "
					+ "is too small, minimum is " + meta.getMin());
			}
			if (current.doubleValue() > meta.getMaxFloat())
			{
				throw new ConfigurationException(getKeyDescription(name) + " parameter value "
					+ "is too big, maximum is " + meta.getMax());
			}
		} else
		{
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

	public Double getDoubleValue(String name) throws ConfigurationException
	{
		Double retVal = getDoubleValueNoCheck(name);
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

	@SuppressWarnings("unchecked")
	public <T> Class<? extends T> getClassValue(String name, Class<T> desiredBase) throws ConfigurationException
	{
		String val = getValue(name);
		if (val == null)
			return null;
		try
		{
			Class<?> cls = Class.forName(val);
			if (!desiredBase.isAssignableFrom(cls))
				throw new ConfigurationException("Value " + val + " is not allowed for "
						+ getKeyDescription(name) + ", must be class extending " + desiredBase);
			return (Class<? extends T>) cls;
		} catch (ClassNotFoundException e)
		{
			throw new ConfigurationException("Value " + val + " is not allowed for "
					+ getKeyDescription(name) + ", must be a class name");
		}
		
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
		Set<String> keys = numericalKeys ? getSortedNumKeys(base, false) : getSortedStringKeys(base, false);
		
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
	
	private synchronized Set<String> getSortedNumKeys(String base, boolean allowListSubKeys)
	{
		SortedSet<Integer> keys = new TreeSet<Integer>();
		Set<Object> allKeys = properties.keySet();
		for (Object keyO: allKeys)
		{
			String key = (String) keyO;
			if (key.startsWith(base))
			{
				String post = key.substring(base.length());
				int dot = post.indexOf('.');
				if (dot != -1 && allowListSubKeys)
					post = post.substring(0, dot);
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

	private synchronized Set<String> getSortedStringKeys(String base, boolean allowListSubKeys)
	{
		SortedSet<String> keys = new TreeSet<String>();
		Set<Object> allKeys = properties.keySet();
		for (Object keyO: allKeys)
		{
			String key = (String) keyO;
			if (key.startsWith(base))
			{
				String post = key.substring(base.length());
				int dot = post.indexOf('.');
				if (dot != -1 && allowListSubKeys)
					post = post.substring(0, dot);
				else if (dot != -1 && !allowListSubKeys)
				{
					log.warn("Property list key '" + key + 
							"' should not posses a dot: '" +
							post + "'. Ignoring.");
					continue;
				}
					
				keys.add(base+post);
			}
		}
		return keys;
	}
	
	/**
	 * @param listKey
	 * @return list of keys defined for the structured list. The returned keys can be iterated and
	 * glued with an actual interesting parameter which is a member of this structured list.
	 */
	public synchronized Set<String> getStructuredListKeys(String listKey)
	{
		PropertyMD listMeta = metadata.get(listKey);
		if (listMeta == null || listMeta.getType() != PropertyMD.Type.STRUCTURED_LIST)
			throw new IllegalArgumentException("The " + listKey + " is not a structured list property");
		Set<String> keys = listMeta.numericalListKeys() ? getSortedNumKeys(prefix+listKey, true) : 
			getSortedStringKeys(prefix+listKey, true);
		Set<String> ret = new LinkedHashSet<String>();
		int prefixLen = prefix.length();
		for (String key: keys)
		{
			key = key.substring(prefixLen);
			ret.add(key+'.');
		}
		return ret;
	}
	
	protected void logValue(String name, String val) 
	{
		warned.add(name);
		PropertyMD meta = getMetadata(name);
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
	
	/**
	 * @param key a full key
	 * @return value of a raw property, i.e. without any metadata checking, usage of prefix etc.
	 */
	public synchronized String getRawProperty(String key)
	{
		return properties.getProperty(key);
	}
	
	/**
	 * Only for use in the package
	 * @return
	 */
	Logger getLoger()
	{
		return log;
	}
	
	@Override
	public PropertiesHelper clone()
	{
		PropertiesHelper ret = new PropertiesHelper(prefix, properties, metadata, log);
		cloneTo(ret);
		return ret;
	}

	protected void cloneTo(PropertiesHelper to)
	{
		to.warned.addAll(this.warned);
		to.genericListeners.addAll(this.genericListeners);
		to.propertyFocusedListeners.putAll(this.propertyFocusedListeners);
	}
}






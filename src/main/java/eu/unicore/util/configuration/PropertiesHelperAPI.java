/*
 * Copyright (c) 2016 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.io.File;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

/**
 * Interface of {@link PropertiesHelper} class. Useful sometimes, when lack of multiinheritance 
 * in Java makes lfie difficult.
 * @author K. Benedyczak
 */
public interface PropertiesHelperAPI
{

	void setProperties(Properties properties) throws ConfigurationException;

	void setProperty(String key, String value);

	void addPropertyChangeListener(PropertyChangeListener listener);

	void removePropertyChangeListener(PropertyChangeListener listener);

	/**
	 * 
	 * @param key
	 * @return string with a full name of the key and its description if set.
	 */
	String getKeyDescription(String key);

	String getValue(String name);

	Long getLongValue(String name) throws ConfigurationException;

	Integer getIntValue(String name) throws ConfigurationException;

	Double getDoubleValue(String name) throws ConfigurationException;

	Boolean getBooleanValue(String name) throws ConfigurationException;

	<T> Class<? extends T> getClassValue(String name, Class<T> desiredBase)
			throws ConfigurationException;

	/**
	 * Returns the value of name key as a provided enum class instance. Important: mapping of string
	 * value to enum label is done in case insensitive way. Therefore if your enum constants differ
	 * only in case, do not use this method.
	 * @param name
	 * @param type
	 * @return
	 * @throws ConfigurationException
	 */
	<T extends Enum<T>> T getEnumValue(String name, Class<T> type)
			throws ConfigurationException;

	/**
	 * See {@link #getFileValue(String, boolean, boolean)}. This version converts the result
	 * to String, handling nulls.
	 */
	String getFileValueAsString(String name, boolean isDirectory) throws ConfigurationException;

	/**
	 * Returns a property value interpreted as a {@link File}. 
	 * The file must exist and must be readable.
	 * @param name
	 * @param isDirectory whether the File must be a directory (true) or a plain file (false)
	 * @return
	 * @throws ConfigurationException
	 */
	File getFileValue(String name, boolean isDirectory) throws ConfigurationException;

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
	String getSubkeyValue(String key, String subKey);

	/**
	 * @see #getSubkeyValue(String, String)
	 * @param key
	 * @param subKey
	 * @return
	 */
	Boolean getSubkeyBooleanValue(String key, String subKey);

	/**
	 * @see #getSubkeyValue(String, String)
	 * @param key
	 * @param subKey
	 * @return
	 */
	Integer getSubkeyIntValue(String key, String subKey);

	/**
	 * @see #getSubkeyValue(String, String)
	 * @param key
	 * @param subKey
	 * @return
	 */
	Long getSubkeyLongValue(String key, String subKey);

	/**
	 * @see #getSubkeyValue(String, String)
	 * @param key
	 * @param subKey
	 * @return
	 */
	<T extends Enum<T>> T getSubkeyEnumValue(String key, String subKey, Class<T> type);

	/**
	 * Returns a string value which can be localized. It is assumed that the given key can have subkeys.
	 * A 'key.language_country' alue is returned if present. If not then the 'key.language'. If it is also
	 * absent then the {@link #getValue(String)} is used.
	 * @param key
	 * @param locale
	 * @return
	 */
	String getLocalizedValue(String key, Locale locale);

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
	List<String> getListOfValues(String prefix2);

	/**
	 * @param listKey
	 * @return list of keys defined for the structured list. The returned keys can be iterated and
	 * glued with an actual interesting parameter which is a member of this structured list.
	 */
	Set<String> getStructuredListKeys(String listKey);

	boolean isSet(String name);

	/**
	 * @param key a full key
	 * @return value of a raw property, i.e. without any metadata checking, usage of prefix etc.
	 */
	String getRawProperty(String key);

	PropertiesHelper clone();

}
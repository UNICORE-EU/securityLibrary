/*
 * Copyright (c) 2017 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Utility class supporting {@link Properties} includes. Scans the given properties object for 
 * include statements, loads the given properties and adds them to the original object. 
 * Checks for conflicts. 
 * 
 * @author K. Benedyczak
 */
public class ConfigIncludesProcessor
{
	public static final String INCLUDE = "$include.";

	public static void processIncludes(Properties src)
	{
		Map<String, String> includes = new HashMap<>();
		src.forEach((keyO, value) -> {
			String key = (String) keyO;
			if (key.startsWith(INCLUDE))
				includes.put(key, (String)value);
		});
		includes.forEach((keyO, value) -> {
			src.remove(keyO);
			processInclude(src, (String)value);
		});
	}

	public static void addIncludedProperties(Properties target, Properties included, String fromFile)
	{
		Map<String, String> includes = new HashMap<>();
		included.forEach((keyO, value) -> {
			String key = (String) keyO;
			if (target.containsKey(key))
				throw new ConfigurationException("Duplicate key " + key 
						+ " found in the included configuration from " 
						+ fromFile);
			if (key.startsWith(INCLUDE))
				includes.put(key, (String)value);
			else
				target.put(key, value);
		});
		includes.forEach((keyO, value) -> 
			processInclude(target, (String)value)
		);
	}
	
	private static void processInclude(Properties src, String includedFile)
	{
		Properties included;
		try
		{
			included = FilePropertiesHelper.load(includedFile);
		} catch (IOException e)
		{
			throw new ConfigurationException("Can not load an included "
					+ "configuration file " + includedFile, e);
		}
		
		addIncludedProperties(src, included, includedFile);
	}
}

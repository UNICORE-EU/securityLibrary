/*
 * Copyright (c) 2017 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * Utility class supporting {@link Properties} includes. Scans the given properties object for 
 * include statements, loads the given properties and adds them to the original object. 
 * Checks for conflicts. 
 * 
 * @author K. Benedyczak
 */
public class ConfigIncludesProcessor
{
	private Logger log;
	public static final String INCLUDE = "$include.";

	public ConfigIncludesProcessor(Logger log)
	{
		this.log = log;
	}

	public static Properties preprocess(Properties src, Logger log)
	{
		ConfigIncludesProcessor processor = new ConfigIncludesProcessor(log);
		return processor.processIncludes(src);
	}
	
	public Properties processIncludes(Properties src)
	{
		Properties withVars = VariablesProcessor.process(src, log);
		Map<String, String> includes = new HashMap<>();
		withVars.forEach((keyO, value) -> {
			String key = (String) keyO;
			if (key.startsWith(INCLUDE))
				includes.put(key, (String)value);
		});
		includes.forEach((keyO, value) -> {
			withVars.remove(keyO);
			processInclude(withVars, (String)value);
		});
		return withVars;
	}

	public void addIncludedProperties(Properties target, Properties included, String fromFile)
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
	
	private void processInclude(Properties src, String includedFile)
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
		Properties withVars = VariablesProcessor.process(included, log);
		addIncludedProperties(src, withVars, includedFile);
	}
}

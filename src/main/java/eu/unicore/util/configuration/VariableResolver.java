/*
 * Copyright (c) 2017 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * Maintains a list of defined variables and allow for resolving them.
 * Order is as follows (first matchin is used): 
 * <ol>
 * <li> System Java properties (typically from command line -D)
 * <li> environment variables 
 * <li> config file-defined variables
 * </ol>
 * @author K. Benedyczak
 */
public class VariableResolver
{
	protected Logger log;
	private Map<String, String> configVariables = new HashMap<>();
	
	public VariableResolver(Logger log)
	{
		this.log = log;
	}

	public void addVariable(String variable, String value)
	{
		configVariables.put(variable, value);
	}

	public String resolve(String variable)
	{
		String resolved = System.getProperty(variable);
		if (resolved != null)
		{
			log.trace("Using system property as a source for " 
					+ variable + ": " + resolved);
			return resolved;
		}
		
		resolved = System.getenv(variable);
		if (resolved != null)
		{
			log.trace("Using environment variable as a source for " 
					+ variable + ": " + resolved);
			return resolved;
		}
		
		resolved = configVariables.get(variable);
		if (resolved != null)
		{
			log.trace("Using config file defined variable as a source for " 
					+ variable + ": " + resolved);
			return resolved;
		}
		
		throw new ConfigurationException("Variable " + variable + " is not defined");
	}
}

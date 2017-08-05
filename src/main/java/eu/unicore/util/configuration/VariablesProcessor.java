/*
 * Copyright (c) 2017 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

/**
 * Substitutes all variables using the given variables processor.
 * First variables defined in configuration are resolved.
 * <p>
 * property is defined as 
 * <pre>
 * $var.PROP = dynamic
 * </pre>
 * and is used:
 * <pre>
 * some.property = Value with ${PROP} variable 
 * </pre>
 * 
 * @author K. Benedyczak
 */
public class VariablesProcessor
{
	public static final String VARIABLE_PFX = "$var.";
	
	public static Properties process(Properties properties, Logger log)
	{
		VariableResolver resolver = new VariableResolver(log);
		Properties ret = new Properties();

		properties.forEach((keyO, valueO) -> {
			String key = (String) keyO;
			if (key.startsWith(VARIABLE_PFX))
			{
				String var = key.substring(VARIABLE_PFX.length());
				String value = substitute((String) valueO, resolver);
				resolver.addVariable(var, value);
			}
		});
		
		properties.forEach((keyO, valueO) -> {
			String key = (String) keyO;
			if (!key.startsWith(VARIABLE_PFX))
			{
				String value = substitute((String) valueO, resolver);
				ret.setProperty(key, value);
			}
		});
		return ret;
	}

	private static String substitute(String value, VariableResolver resolver)
	{
		Pattern pattern = Pattern.compile("\\$\\{(.+?)\\}");
		Matcher matcher = pattern.matcher(value);
		StringBuffer buffer = new StringBuffer();

		while (matcher.find())
		{
			String variable = resolver.resolve(matcher.group(1));
			matcher.appendReplacement(buffer, "");
			buffer.append(variable);
		}
		matcher.appendTail(buffer);
		return buffer.toString();
	}
}

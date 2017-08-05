/*
 * Copyright (c) 2017 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.configuration;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.junit.Test;

import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.VariablesProcessor;

public class VariablesProcessorTest
{
	private static final Logger log = Logger.getLogger(VariablesProcessorTest.class);
	
	@Test
	public void shouldResolveConfigVariable() throws IOException
	{
		Properties props = new Properties();
		props.setProperty("$var.var1", "Dynamic");
		props.setProperty("p", "some${var1}Value");
		
		Properties processed = VariablesProcessor.process(props, log);
		
		assertThat(processed.getProperty("p"), is("someDynamicValue"));
	}

	@Test
	public void shouldFailOnUnknownVariable() throws IOException
	{
		Properties props = new Properties();
		props.setProperty("p", "some${var2}Value");

		try
		{
			VariablesProcessor.process(props, log);
			fail("Should throw exception");
		} catch (ConfigurationException e)
		{
			assertThat(e.getMessage(), containsString("var2"));
		}
	}

	@Test
	public void shouldUseSystemPropertyAsValue() throws IOException
	{
		Properties props = new Properties();
		props.setProperty("p", "some${java.version}Value");
		
		Properties processed = VariablesProcessor.process(props, log);
		
		assertThat(processed.getProperty("p"), is("some" + 
				System.getProperty("java.version") + "Value"));
	}

	@Test
	public void systemPropertyShouldOverrideConfigVariable() throws IOException
	{
		Properties props = new Properties();
		props.setProperty("$var.java.version", "CONFIG-DEFINED");
		props.setProperty("p", "some${java.version}Value");
		
		Properties processed = VariablesProcessor.process(props, log);
		
		assertThat(processed.getProperty("p"), is("some" + 
				System.getProperty("java.version") + "Value"));
	}
	
	@Test
	public void shouldUseEnvVariableAsValue() throws IOException
	{
		Properties props = new Properties();
		String firstEnvVar = System.getenv().keySet().iterator().next();
		
		props.setProperty("p", "some${" + firstEnvVar + "}Value");
		
		Properties processed = VariablesProcessor.process(props, log);
		
		assertThat(processed.getProperty("p"), is("some" + 
				System.getenv(firstEnvVar) + "Value"));
	}

}

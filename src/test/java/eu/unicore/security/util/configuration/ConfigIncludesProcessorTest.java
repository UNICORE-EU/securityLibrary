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

import eu.unicore.util.configuration.ConfigIncludesProcessor;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.FilePropertiesHelper;

public class ConfigIncludesProcessorTest
{
	private static final Logger log = Logger.getLogger(ConfigIncludesProcessorTest.class);
	
	@Test
	public void shouldIncludeRecursivelyIncludedProperties() throws IOException
	{
		Properties ret = FilePropertiesHelper.load(
				"src/test/resources/props/base.properties");
		ret = ConfigIncludesProcessor.preprocess(ret, log); 
		
		assertThat(ret.getProperty("regular.property"), is("value1"));
		assertThat(ret.getProperty("regular.property2"), is("value2"));
		assertThat(ret.getProperty("regular.property3"), is("value3"));
		assertThat(ret.size(), is(3));
	}

	@Test
	public void shouldIncludeFromFileGivenWithVariable() throws IOException
	{
		Properties ret = FilePropertiesHelper.load(
				"src/test/resources/props/baseWithVars.properties");
		ret = ConfigIncludesProcessor.preprocess(ret, log); 
		
		assertThat(ret.getProperty("regular.property"), is("value1"));
		assertThat(ret.getProperty("regular.property2"), is("value2"));
		assertThat(ret.getProperty("regular.property3"), is("Dynamic"));
		assertThat(ret.size(), is(3));
	}
	
	@Test
	public void shouldFailOnDuplicateKeyInIncludedProperties() throws IOException
	{
		try
		{
			ConfigIncludesProcessor.preprocess(FilePropertiesHelper.load(
				"src/test/resources/props/baseWithDuplicate.properties"), log);
			fail("Should throw an exception");
		} catch (ConfigurationException e)
		{
			assertThat(e.getMessage(), containsString("Duplicate"));
			assertThat(e.getMessage(), containsString("regular.property"));
		}

	}
}

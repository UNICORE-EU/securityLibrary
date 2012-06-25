/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.ProxySupport;
import eu.unicore.util.configuration.AsciidocFormatter;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.DocumentationReferenceMeta;
import eu.unicore.util.configuration.DocumentationReferencePrefix;
import eu.unicore.util.configuration.FilePropertiesHelper;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;
import junit.framework.TestCase;

public class PropertiesHelperTest extends TestCase
{
	private static final Logger log = Logger.getLogger(PropertiesHelperTest.class);
	
	@DocumentationReferencePrefix
	private static final String PREFIX = "prefix.";
	
	@DocumentationReferenceMeta
	private static final Map<String, PropertyMD> METADATA = new HashMap<String, PropertyMD>();
	static 
	{
		METADATA.put("p01", new PropertyMD(ProxySupport.ALLOW));
		METADATA.put("p02", new PropertyMD().setEnum(CrlCheckingMode.IF_VALID));
		METADATA.put("p03", new PropertyMD("600").setLong());
		METADATA.put("p04", new PropertyMD("600"));
		METADATA.put("p05", new PropertyMD("600").setMin(-222));
		METADATA.put("p06", new PropertyMD("600").setMax(876));
		METADATA.put("p07", new PropertyMD("600").setMin(-222).setMax(987));
		METADATA.put("p08", new PropertyMD("true").setDescription("Example decription of the boolean property blah blah blah"));
		METADATA.put("p09", new PropertyMD().setMandatory());
		METADATA.put("p10", new PropertyMD().setPath());
		METADATA.put("p11.", new PropertyMD().setList(true).setDescription("List of values blah blah blah"));
		METADATA.put("p12", new PropertyMD().setCanHaveSubkeys());
		METADATA.put("p13.", new PropertyMD().setList(false).setDescription("List of values blah blah blah"));
	}

	private static Properties load(String input)
	{
		Properties ret = new Properties();
		try
		{
			ret.load(new ByteArrayInputStream(input.getBytes()));
		} catch (IOException e)
		{
			e.printStackTrace();
			throw new RuntimeException(e);
		}
		return ret;
	}
	
	public void testParsingMandatory()
	{
		String PROP = "prefix.p01 = ALLOW";
		try
		{
			new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			fail("Managed to load cfg without mandatory");
		} catch (ConfigurationException e)
		{
			assertTrue(e.getMessage().contains("p09"));
		}
	}

	public void testParsingDefault()
	{
		String PROP = "prefix.p09=mandatory\nprefix.p01 = ALLOW";
		try
		{
			PropertiesHelper helper = new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			assertEquals(600, helper.getIntValue("p04").intValue());
		} catch (ConfigurationException e)
		{
			fail(e.toString());
		}
	}
	
	public void testParsingUnknown()
	{
		String PROP = "prefix.p09=mandatory\nprefix.foo = bar";
		try
		{
			new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			fail("Managed to load cfg with unknown");
		} catch (ConfigurationException e)
		{
			assertTrue(e.getMessage().contains("foo"));
		}
	}

	public void testParsingRanges()
	{
		String PROP = "prefix.p09=mandatory\nprefix.p07 = -300";
		try
		{
			new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			fail("Managed to load cfg out of range");
		} catch (ConfigurationException e)
		{
			assertTrue(e.getMessage().contains("p07"));
		}
		
		PROP = "prefix.p09=mandatory\nprefix.p07 = 10000";
		try
		{
			new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			fail("Managed to load cfg out of range");
		} catch (ConfigurationException e)
		{
			assertTrue(e.getMessage().contains("p07"));
		}
		
		PROP = "prefix.p09=mandatory\nprefix.p07 = 100";
		new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
	}

	public void testParsingEnums()
	{
		String PROP = "prefix.p09=mandatory\nprefix.p01 = DENY";
		try
		{
			PropertiesHelper helper = new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			assertEquals(ProxySupport.DENY, helper.getEnumValue("p01", ProxySupport.class));
		} catch (ConfigurationException e)
		{
			fail(e.toString());
		}
	}

	public void testParsingPaths()
	{
		String PROP = "prefix.p09=mandatory\nprefix.p10 = src/test/resources";
		try
		{
			PropertiesHelper helper = new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			File f = helper.getFileValue("p10", true);
			assertEquals("src/test/resources", f.getPath());
			
			try
			{
				f = helper.getFileValue("p10", false);
				fail();
			} catch (ConfigurationException e)
			{
				//ok
			}
		} catch (ConfigurationException e)
		{
			fail(e.toString());
		}
	}

	public void testParsingLists()
	{
		String PROP = "prefix.p09=mandatory\nprefix.p11.22 = ola\nprefix.p11.100 = ala\nprefix.p13.22 = ola\nprefix.p13.100 = ala";
		try
		{
			PropertiesHelper helper = new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			List<String> vals = helper.getListOfValues("p11.");
			assertEquals(2, vals.size());
			assertEquals("ola", vals.get(0));
			assertEquals("ala", vals.get(1));
			vals = helper.getListOfValues("p13.");
			assertEquals(2, vals.size());
			assertEquals("ala", vals.get(0));
			assertEquals("ola", vals.get(1));
		} catch (ConfigurationException e)
		{
			e.printStackTrace();
			fail(e.toString());
		}
		
		PROP = "prefix.p09=mandatory\nprefix.p11.zz = ola";
		try
		{
			new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			fail("Managed to use property with wrong keys for list (non numbers)");
		} catch (ConfigurationException e)
		{
			assertTrue(e.getMessage().contains("p11.zz"));
		}
	}

	public void testParsingSubkeys()
	{
		String PROP = "prefix.p09=mandatory\nprefix.p12 = def\nprefix.p12.sub = ala";
		try
		{
			PropertiesHelper helper = new PropertiesHelper(PREFIX, load(PROP), METADATA, log);
			assertEquals("def", helper.getSubkeyValue("p12", "foo"));
			assertEquals("ala", helper.getSubkeyValue("p12", "sub"));
		} catch (ConfigurationException e)
		{
			fail(e.toString());
		}
	}
	
	public void testFileHelper() throws Exception
	{
		File cfg = new File("target/log4j.properties");
		FileUtils.copyFile(new File("src/test/resources/log4j.properties"), cfg);
		Map<String, PropertyMD> meta = new HashMap<String, PropertyMD>();
		meta.put("log4j", new PropertyMD().setCanHaveSubkeys());
		FilePropertiesHelper helper = new FilePropertiesHelper("", cfg, meta, log);
		assertEquals(false, helper.reloadIfChanged());
		FileWriter fw = new FileWriter(cfg);
		fw.append("\n\n");
		fw.close();
		assertEquals(true, helper.reloadIfChanged());
	}
	
	public void testAsciidocReference()
	{
		AsciidocFormatter formatter = new AsciidocFormatter();
		System.out.println(formatter.format(PREFIX, METADATA));
	}
	
	public void testReflection()
	{
		try
		{
			File f = new File("target/generated-doc.txt");
			f.delete();
			AsciidocFormatter.main("target", PropertiesHelperTest.class.getName()+"|"+f.getName());
			assertTrue(f.exists());
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.toString());
		}
	}	
}

/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.ProxySupport;
import junit.framework.TestCase;

public class PropertiesHelperTest extends TestCase
{
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
		METADATA.put("p11.", new PropertyMD().setList().setDescription("List of values blah blah blah"));
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
			AsciidocFormatter.main("target", PropertiesHelperTest.class.getName(), 
					f.getName());
			assertTrue(f.exists());
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.toString());
		}
	}
	
}

/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.util.HashMap;
import java.util.Map;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.ProxySupport;
import junit.framework.TestCase;

public class PropertiesHelperTest extends TestCase
{
	private static final Map<String, PropertyMD> META = new HashMap<String, PropertyMD>();
	static 
	{
		META.put("p01", new PropertyMD(ProxySupport.ALLOW));
		META.put("p02", new PropertyMD().setEnum(CrlCheckingMode.IF_VALID));
		META.put("p03", new PropertyMD("600").setLong());
		META.put("p04", new PropertyMD("600"));
		META.put("p05", new PropertyMD("600").setMin(-222));
		META.put("p06", new PropertyMD("600").setMax(876));
		META.put("p07", new PropertyMD("600").setMin(-222).setMax(987));
		META.put("p08", new PropertyMD("true").setDescription("Example decription of the boolean property blah blah blah"));
		META.put("p09", new PropertyMD().setMandatory());
		META.put("p10", new PropertyMD().setPath());
		META.put("p11.", new PropertyMD().setList().setDescription("List of values blah blah blah"));
	}

	public void testAsciidocReference()
	{
		AsciidocFormater formatter = new AsciidocFormater();
		System.out.println(formatter.format("prefix.", META));
	}
}

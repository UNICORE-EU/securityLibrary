/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 29-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.unicore.security.XACMLAttribute.Type;

import junit.framework.TestCase;



public class SubjectAttributesHolderTest extends TestCase
{
	public void testSetIncarnation()
	{
		Map<String, String[]> defA = new HashMap<String, String[]>(); 
		Map<String, String[]> validA = new HashMap<String, String[]>();
		SubjectAttributesHolder holder = new SubjectAttributesHolder();
		
		defA.put("1", new String[] {"a", "b"});
		validA.put("1", new String[] {"a", "b"});
		
		validA.put("3", new String[] {"a", "b"});

		defA.put("4", new String[] {"a", "b"});
		validA.put("4", new String[] {"a", "c", "b", "d"});
		
		defA.put("5", new String[] {});
		validA.put("5", new String[] {});

		
		holder.setAllIncarnationAttributes(defA, validA);
		
		Map<String, String[]> defA2 = holder.getDefaultIncarnationAttributes();
		Map<String, String[]> validA2 = holder.getValidIncarnationAttributes();
		
		assertTrue(defA2.containsKey("1") && defA2.get("1").length == 2);
		assertTrue(validA2.containsKey("1") && validA2.get("1").length == 2);

		assertTrue(!defA2.containsKey("3"));
		assertTrue(validA2.containsKey("3") && validA2.get("3").length == 2);

		assertTrue(defA2.containsKey("4") && defA2.get("4").length == 2);
		assertTrue(validA2.containsKey("4") && validA2.get("4").length == 4);

		assertTrue(defA2.containsKey("5") && defA2.get("5").length == 0);
		assertTrue(validA2.containsKey("5") && validA2.get("5").length == 0);
		
		try 
		{
			defA.put("6", new String[] {"a"});
			validA.put("6", new String[] {"b", "c"});
			
			holder.setAllIncarnationAttributes(defA, validA);
			fail("Managed to add attribute with a default not in valid set");
		} catch(IllegalArgumentException e)
		{
			
		}
	}
	
	public void testAddMerging()
	{
		Map<String, String[]> defA = new HashMap<String, String[]>(); 
		Map<String, String[]> validA = new HashMap<String, String[]>();
		List<XACMLAttribute> xacmlA = new ArrayList<XACMLAttribute>();
		defA.put("1", new String[] {"a", "b"});
		validA.put("1", new String[] {"a", "b"});
		defA.put("2", new String[] {"a"});
		validA.put("2", new String[] {"a", "c"});
		xacmlA.add(new XACMLAttribute("x1", "v1", Type.STRING));
		xacmlA.add(new XACMLAttribute("x1", "v2", Type.STRING));
		xacmlA.add(new XACMLAttribute("x2", "v1", Type.STRING));
		
		SubjectAttributesHolder holder = new SubjectAttributesHolder(xacmlA, defA, validA);
		
		Map<String, String[]> defANew = new HashMap<String, String[]>(); 
		Map<String, String[]> validANew = new HashMap<String, String[]>();
		List<XACMLAttribute> xacmlANew = new ArrayList<XACMLAttribute>();
		defANew.put("3", new String[] {"a", "b"});
		validANew.put("3", new String[] {"a", "b"});
		defANew.put("2", new String[] {"b"});
		validANew.put("2", new String[] {"a", "b"});
		xacmlANew.add(new XACMLAttribute("x1", "v1", Type.STRING));
		xacmlANew.add(new XACMLAttribute("x1", "v3", Type.STRING));
		xacmlANew.add(new XACMLAttribute("x3", "v1", Type.STRING));
		SubjectAttributesHolder holderNew = new SubjectAttributesHolder(xacmlANew, defANew, validANew);

		
		holder.addAllMerging(holderNew);
		
		Map<String, String[]> defA2 = holder.getDefaultIncarnationAttributes();
		Map<String, String[]> validA2 = holder.getValidIncarnationAttributes();
		List<XACMLAttribute> xacmlA2 = holder.getXacmlAttributes();
		
		assertTrue(defA2.containsKey("1") && defA2.get("1").length == 2);
		assertTrue(validA2.containsKey("1") && validA2.get("1").length == 2);
		assertTrue(defA2.containsKey("2") && defA2.get("2").length == 1);
		assertTrue(validA2.containsKey("2") && validA2.get("2").length == 3);
		assertTrue(defA2.containsKey("3") && defA2.get("3").length == 2);
		assertTrue(validA2.containsKey("3") && validA2.get("3").length == 2);

		assertTrue(xacmlA2.size() == 5);
	}


	public void testAddOverwrite()
	{
		Map<String, String[]> defA = new HashMap<String, String[]>(); 
		Map<String, String[]> validA = new HashMap<String, String[]>();
		List<XACMLAttribute> xacmlA = new ArrayList<XACMLAttribute>();
		defA.put("1", new String[] {"a", "b"});
		validA.put("1", new String[] {"a", "b"});
		defA.put("2", new String[] {"a", "c"});
		validA.put("2", new String[] {"a", "c"});
		xacmlA.add(new XACMLAttribute("x1", "v1", Type.STRING));
		xacmlA.add(new XACMLAttribute("x1", "v2", Type.STRING));
		xacmlA.add(new XACMLAttribute("x2", "v1", Type.STRING));
		
		SubjectAttributesHolder holder = new SubjectAttributesHolder(xacmlA, defA, validA);
		
		Map<String, String[]> defANew = new HashMap<String, String[]>(); 
		Map<String, String[]> validANew = new HashMap<String, String[]>();
		List<XACMLAttribute> xacmlANew = new ArrayList<XACMLAttribute>();
		defANew.put("3", new String[] {"a", "b"});
		validANew.put("3", new String[] {"a", "b"});
		defANew.put("2", new String[] {"b"});
		validANew.put("2", new String[] {"a", "b"});
		xacmlANew.add(new XACMLAttribute("x1", "v1", Type.STRING));
		xacmlANew.add(new XACMLAttribute("x1", "v3", Type.STRING));
		xacmlANew.add(new XACMLAttribute("x3", "v1", Type.STRING));
		SubjectAttributesHolder holderNew = new SubjectAttributesHolder(xacmlANew, defANew, validANew);

		
		holder.addAllOverwritting(holderNew);
		
		Map<String, String[]> defA2 = holder.getDefaultIncarnationAttributes();
		Map<String, String[]> validA2 = holder.getValidIncarnationAttributes();
		List<XACMLAttribute> xacmlA2 = holder.getXacmlAttributes();
		
		assertTrue(defA2.containsKey("1") && defA2.get("1").length == 2);
		assertTrue(validA2.containsKey("1") && validA2.get("1").length == 2);
		assertTrue(defA2.containsKey("2") && defA2.get("2").length == 1);
		assertTrue(validA2.containsKey("2") && validA2.get("2").length == 2);
		assertTrue(defA2.containsKey("3") && defA2.get("3").length == 2);
		assertTrue(validA2.containsKey("3") && validA2.get("3").length == 2);

		assertTrue(xacmlA2.size() == 4);
	}
	
	public void testPreferedVo()
	{
		SubjectAttributesHolder holder = new SubjectAttributesHolder();
		
		assertFalse(holder.isPresent());
		
		holder.setPreferredVos(new String[] {"/0", "/a", "/b", "/c"});
		assertEquals(0, holder.getVoPreferrence("/0"));
		assertEquals(1, holder.getVoPreferrence("/a"));
		assertEquals(2, holder.getVoPreferrence("/b"));
		assertTrue(holder.getVoPreferrence("/z") < 0);
		
		Map<String, String[]> attributes = new HashMap<String, String[]>();
		attributes.put("a1", new String[] {"val1"});
		try
		{
			holder.setPreferredVoIncarnationAttributes("/z", attributes);
			fail("managed to set selected VO which is not among preferred by the user");
		} catch (IllegalArgumentException e)
		{
			//ok
		}
		
		holder.setPreferredVoIncarnationAttributes("/b", attributes);
		Map<String, String[]> ret = holder.getPreferredVoIncarnationAttributes();
		assertEquals(1, ret.size());
		assertNotNull(ret.get("a1"));
		assertEquals(1, ret.get("a1").length);
		assertEquals("val1", ret.get("a1")[0]);
		
		Map<String, String[]> attributes2 = new HashMap<String, String[]>();
		attributes2.put("a2", new String[] {"val2"});

		holder.setPreferredVoIncarnationAttributes("/a", attributes2);
		Map<String, String[]> ret2 = holder.getPreferredVoIncarnationAttributes();
		assertEquals(1, ret2.size());
		assertNotNull(ret2.get("a2"));
		assertEquals(1, ret2.get("a2").length);
		assertEquals("val2", ret2.get("a2")[0]);
		
		assertFalse(holder.isPresent());
		assertFalse(holder.validateVoIncarnationAttributes());
		
		Map<String, String[]> attributesDef = new HashMap<String, String[]>();
		attributesDef.put("a2", new String[] {"val2", "val3"});
		attributesDef.put("a3", new String[] {"val3"});
		
		holder.setAllIncarnationAttributes(attributesDef, attributesDef);
		
		assertTrue(holder.isPresent());
		assertTrue(holder.validateVoIncarnationAttributes());
		
		Map<String, String[]> ret3 = holder.getIncarnationAttributes();
		assertEquals(2, ret3.size());
		assertNotNull(ret3.get("a2"));
		assertEquals(1, ret3.get("a2").length);
		assertEquals("val2", ret3.get("a2")[0]);
		assertNotNull(ret3.get("a3"));
		assertEquals(1, ret3.get("a3").length);
		assertEquals("val3", ret3.get("a3")[0]);
		
		
		SubjectAttributesHolder holder2 = new SubjectAttributesHolder(new String[] {"/0"});
		Map<String, String[]> attributesVoNew = new HashMap<String, String[]>();
		attributesVoNew.put("a2", new String[] {"val3"});
		holder2.setPreferredVoIncarnationAttributes("/0", attributesVoNew);
		holder.addAllOverwritting(holder2);
		
		Map<String, String[]> ret4 = holder.getPreferredVoIncarnationAttributes();
		assertEquals(1, ret4.size());
		assertNotNull(ret4.get("a2"));
		assertEquals(1, ret4.get("a2").length);
		assertEquals("val3", ret4.get("a2")[0]);
	}

	
	
	
	public void testToString()
	{
		Map<String, String[]> defA = new HashMap<String, String[]>(); 
		Map<String, String[]> validA = new HashMap<String, String[]>();
		Map<String, String[]> voA = new HashMap<String, String[]>();
		List<XACMLAttribute> xacmlA = new ArrayList<XACMLAttribute>();
		defA.put("aa1", new String[] {"a", "b"});
		validA.put("aa1", new String[] {"a", "b"});
		defA.put("aa2", new String[] {"a", "c"});
		validA.put("aa2", new String[] {"a", "c"});
		voA.put("aa3", new String[] {"g"});
		xacmlA.add(new XACMLAttribute("x1", "v1", Type.STRING));
		xacmlA.add(new XACMLAttribute("x1", "v2", Type.STRING));
		xacmlA.add(new XACMLAttribute("x2", "v1", Type.STRING));
		
		SubjectAttributesHolder holder = new SubjectAttributesHolder(xacmlA, defA, validA);
		holder.setPreferredVos(new String[] {"/a"});
		holder.setPreferredVoIncarnationAttributes("/a", voA);
		
		String full = holder.toString();
		assertTrue(full.contains("aa1"));
		assertTrue(full.contains("aa2"));
		assertTrue(full.contains("aa3"));
		assertTrue(full.contains("x1"));
		assertTrue(full.contains("x2"));
		
		SubjectAttributesHolder holder2 = new SubjectAttributesHolder();
		String empty = holder2.toString();
		assertTrue(empty.length() == 0);
	}
}






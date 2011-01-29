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

}






/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 25-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Holds subject's attributes as collected by one or more attribute sources.
 * There are two principal sets of attributes here: incarnation attributes and 
 * extra XACML attributes which are used for authorisation only. For incarnation
 * attributes three structures are stored:
 * <ul> 
 * <li> All permitted attributes, which are used if user specify manually 
 *  a preferred value for an attribute (e.g. an Xlogin to be used) to check if this selection is valid.
 * <li> default attributes (a subset of permitted) which usually can be configured by an admin in attribute source
 *  and are used if user doesn't specify a concrete attribute value to be used.
 * <li> attributes from a preferred VO, which are stored only if AIP is providing attributes for a preferred group
 *  or its parent. Then attributes as established in the preferred VO/group (which might be subgroup of the AIP
 *  base VO/group) are stored.
 * </ul>
 * 
 * This class is used in two ways. It contains a set of methods and constructors 
 * to initialize the object. Additionally there are two methods which allows
 * for combining data from this class with other instance: using merge or overwrite mode. 
 * 
 * @author golbi
 * @see IAttributeSource class in use-core
 */
public class SubjectAttributesHolder implements Serializable
{
	private static final long serialVersionUID = 1L;
	
	private Map<String, List<XACMLAttribute>> xacmlAttributes;
	private Map<String, String[]> defaultIncarnationAttributes;
	private Map<String, String[]> validIncarnationAttributes;
	
	private Map<String, String[]> preferredVoIncarnationAttributes = new HashMap<String, String[]>();
	/**
	 * Stores the actual name of the VO which attributes are in the preferredVOIncarnationAttributes.
	 * Must be one of preferredVos. It can be overwritten if subsequent AIP provides attributes from a VO which
	 * is higher on the preferredVos list.  
	 */
	private String selectedVo;
	private String[] preferredVos;

	
	/**
	 * All structures are initialized to be empty.
	 */
	public SubjectAttributesHolder()
	{
		this(new String[] {});
	}
	
	/**
	 * All structures are initialized to be empty.
	 * Preferred VOs are initially set. 
	 */
	public SubjectAttributesHolder(String[] preferredVos)
	{
		xacmlAttributes = new HashMap<String, List<XACMLAttribute>>();
		defaultIncarnationAttributes = new HashMap<String, String[]>();
		validIncarnationAttributes = new HashMap<String, String[]>();
		this.preferredVos = preferredVos;
	}

	
	/**
	 * No XACML attributes, valid == default
	 * @param incarnationAttributes
	 */
	public SubjectAttributesHolder(Map<String, String[]> incarnationAttributes)
	{
		this(null, incarnationAttributes, incarnationAttributes);
	}

	public SubjectAttributesHolder(Map<String, String[]> defaultIncarnationAttributes,
			Map<String, String[]> validIncarnationAttributes)
	{
		this(null, defaultIncarnationAttributes, validIncarnationAttributes);
	}


	/**
	 * @param xacmlAttributes
	 * @param defaultIncarnationAttributes
	 * @param validIncarnationAttributes
	 */
	public SubjectAttributesHolder(List<XACMLAttribute> xacmlAttributes,
			Map<String, String[]> defaultIncarnationAttributes,
			Map<String, String[]> validIncarnationAttributes)
	{
		setXacmlAttributes(xacmlAttributes);
		setAllIncarnationAttributes(defaultIncarnationAttributes, validIncarnationAttributes);
	}

	/**
	 * Adds all attributes from the argument object. Existing attributes are overwritten:
	 * incarnation attributes with same names are simply replaced. 
	 * In case of XACML attributes all existing with the names contained in the argument
	 * list are removed first. 
	 * 
	 * @param from
	 */
	public void addAllOverwritting(SubjectAttributesHolder from)
	{
		addAllCommon(from);
		if (from.getValidIncarnationAttributes() != null)
			validIncarnationAttributes.putAll(from.getValidIncarnationAttributes());
		if (from.getXacmlAttributes() != null)
		{
			for (XACMLAttribute xacmlAttribute: from.getXacmlAttributes())
				xacmlAttributes.remove(xacmlAttribute.getName());
			for (XACMLAttribute xacmlAttribute: from.getXacmlAttributes())
				addToXACMLList(xacmlAttribute);
		}
	}

	/**
	 * Adds all attributes from the argument object. Existing attributes are merged whenever 
	 * this makes sense: valid values and XACML attributes are merged, defaults for incarnation 
	 * are overridden.
	 * 
	 * @param from
	 */
	public void addAllMerging(SubjectAttributesHolder from)
	{
		addAllCommon(from);
		if (from.getValidIncarnationAttributes() != null)
		{
			for(Map.Entry<String, String[]>e: from.getValidIncarnationAttributes().entrySet())
			{
				String key=e.getKey();
				String[]existing=validIncarnationAttributes.get(key);
				String[]newAttr=e.getValue();
				
				if(existing!=null)
				{
					Set<String> result = new LinkedHashSet<String>();
					for (String existingA: existing)
						result.add(existingA);
					for (String newA: newAttr)
						result.add(newA);
					validIncarnationAttributes.put(key, result.toArray(new String[result.size()]));
				} else
				{
					validIncarnationAttributes.put(key, newAttr);
				}
			}	
		}
		if (from.getXacmlAttributes() != null)
		{
			for (XACMLAttribute xacmlAttribute: from.getXacmlAttributes())
				addToXACMLList(xacmlAttribute);
		}
	}
	
	private void addAllCommon(SubjectAttributesHolder from)
	{
		if (from.getDefaultIncarnationAttributes() != null)
			defaultIncarnationAttributes.putAll(from.getDefaultIncarnationAttributes());
		if (from.getSelectedVo() != null)
		{
			int newPref = getVoPreferrence(from.getSelectedVo());
			if (newPref >= 0 && (selectedVo == null || newPref < getVoPreferrence(selectedVo)))
			{
				selectedVo = from.getSelectedVo();
				preferredVoIncarnationAttributes.putAll(from.getPreferredVoIncarnationAttributes());
			}
		}
	}
	
	
	private void addToXACMLList(XACMLAttribute a)
	{
		List<XACMLAttribute> current = this.xacmlAttributes.get(a.getName());
		if (current == null)
		{
			current = new ArrayList<XACMLAttribute>();
			this.xacmlAttributes.put(a.getName(), current);
		}
		if (!current.contains(a))
			current.add(a);		
	}
	
	public List<XACMLAttribute> getXacmlAttributes()
	{
		List<XACMLAttribute> ret = new ArrayList<XACMLAttribute>();
		Collection<List<XACMLAttribute>> vals = xacmlAttributes.values();
		for (List<XACMLAttribute> val: vals)
			ret.addAll(val);
		return ret;
	}
	
	public void setXacmlAttributes(List<XACMLAttribute> xacmlAttributes)
	{
		this.xacmlAttributes = new HashMap<String, List<XACMLAttribute>>();
		if (xacmlAttributes != null)
		{
			for (XACMLAttribute a: xacmlAttributes)
				addToXACMLList(a);
		}
	}

	/**
	 * @return if preferred VO attributes are not set then default attributes are returned. Otherwise
	 * a map with default attributes overwritten with the preferred VO attributes is returned.   
	 */
	public Map<String, String[]> getIncarnationAttributes()
	{
		if (validateVoIncarnationAttributes()) {
			Map<String, String[]> ret = new HashMap<String, String[]>();
			ret.putAll(getDefaultIncarnationAttributes());
			ret.putAll(getPreferredVoIncarnationAttributes());
			return ret;
		}
		return getDefaultIncarnationAttributes();
	}

	
	public Map<String, String[]> getDefaultIncarnationAttributes()
	{
		return defaultIncarnationAttributes;
	}

	public Map<String, String[]> getValidIncarnationAttributes()
	{
		return validIncarnationAttributes;
	}
	
	/**
	 * @return the preferredVoIncarnationAttributes. May be null if were not set.
	 */
	public Map<String, String[]> getPreferredVoIncarnationAttributes()
	{
		return preferredVoIncarnationAttributes;
	}

	/**
	 * @param exactVo exact VO of the selected attributes 
	 * @param preferredVoIncarnationAttributes the preferredVoIncarnationAttributes to set
	 */
	public void setPreferredVoIncarnationAttributes(String exactVo, 
			Map<String, String[]> preferredVoIncarnationAttributes)
	{
		if (exactVo == null)
			throw new IllegalArgumentException("Preferred VO can not be null");
		for (String vo: preferredVos)
			if (vo.equals(exactVo)) 
			{
				this.selectedVo = exactVo;
				this.preferredVoIncarnationAttributes = preferredVoIncarnationAttributes;
				return;
			}
		throw new IllegalArgumentException("Selected VO must be one of the preferred VOs");
	}

	/**
	 * lower index - higher preference.
	 * Negative value - vo is not preferred.
	 * @param vo
	 * @return
	 */
	public int getVoPreferrence(String vo)
	{
		for (int i=0; i<preferredVos.length; i++)
			if (preferredVos[i].equals(vo))
				return i;
		return -1;
	}
	
	
	
	/**
	 * @return the selectedVo
	 */
	public String getSelectedVo()
	{
		return selectedVo;
	}


	/**
	 * @return the preferredVos
	 */
	public String[] getPreferredVos()
	{
		return preferredVos;
	}

	/**
	 * @param preferredVos the preferredVos to set
	 */
	public void setPreferredVos(String[] preferredVos)
	{
		this.preferredVos = preferredVos;
	}


	/**
	 * 
	 * @return true if preferred VO attributes are set and all values are among valid attributes. Using current UVOS
	 * this should be guaranteed, but we check anyway.
	 */
	public boolean validateVoIncarnationAttributes()
	{
		if (preferredVoIncarnationAttributes.size() == 0)
			return false;
		try
		{
			testSubset(preferredVoIncarnationAttributes, validIncarnationAttributes);
			return true;
		} catch (IllegalArgumentException e)
		{
			return false;
		}
	}

	/**
	 * Sets incarnation attributes. Valid incarnation attributes must be a superset of default incarnation
	 * attributes.  
	 * @param defaultIncarnationAttributes
	 * @param validIncarnationAttributes
	 */
	public void setAllIncarnationAttributes(Map<String, String[]> defaultIncarnationAttributes, 
			Map<String, String[]> validIncarnationAttributes)
	{
		if (defaultIncarnationAttributes == null || validIncarnationAttributes == null)
			throw new IllegalArgumentException("Arguments can not be null");
		testSubset(defaultIncarnationAttributes, validIncarnationAttributes);
		this.defaultIncarnationAttributes = new HashMap<String, String[]>();
		this.defaultIncarnationAttributes.putAll(defaultIncarnationAttributes);
		this.validIncarnationAttributes = new HashMap<String, String[]>();
		this.validIncarnationAttributes.putAll(validIncarnationAttributes);
	}
	
	private static void testSubset(Map<String, String[]> attributes, Map<String, String[]> validAttributes)
	{
		Iterator<Map.Entry<String, String[]>> it = attributes.entrySet().iterator();
		while (it.hasNext()) 
		{
			Map.Entry<String, String[]> defA = it.next();
			if (validAttributes.containsKey(defA.getKey()))
			{
				String[] validVals = validAttributes.get(defA.getKey());
				String[] defaultVals = defA.getValue();
				for (String defaultVal: defaultVals)
				{
					boolean found = false;
					for (String validVal: validVals)
						if (validVal.equals(defaultVal))
						{
							found = true;
							break;
						}
					if (!found)
						throw new IllegalArgumentException("The default incarnation attribute >" + 
								defA.getKey() + "< value >" + defaultVal + 
								"< is not present among valid incarnation attributes.");
				}
			} else
			{
				throw new IllegalArgumentException("The default incarnation attribute " + 
						defA.getKey() + " is not present among valid incarnation attributes.");
			}
		}
		
	}
	
	public boolean isPresent()
	{
		if (defaultIncarnationAttributes.size() > 0)
			return true;
		if (xacmlAttributes.size() > 0)
			return true;
		return false;
	}
	
	private static void outputAttrsMap(StringBuilder sb, Map<String, String[]> attrs)
	{
		Iterator<Entry<String, String[]>> valid = 
			attrs.entrySet().iterator();
		while (valid.hasNext())
		{
			Entry<String, String[]> validE = valid.next();
			sb.append(validE.getKey());
			sb.append(": ");
			sb.append(Arrays.toString(validE.getValue()));
			if (valid.hasNext())
				sb.append("; ");
		}
	}

	public String toString()
	{
		StringBuilder sb = new StringBuilder(1024);
		boolean needEnter = false;
		if (validIncarnationAttributes.size() != 0)
		{
			sb.append("Valid attribute values: ");
			outputAttrsMap(sb, validIncarnationAttributes);
			needEnter = true;
		}
		if (defaultIncarnationAttributes.size() != 0)
		{
			if (needEnter)
				sb.append("\n");
			sb.append("Default attribute values: ");
			outputAttrsMap(sb, defaultIncarnationAttributes);
			needEnter = true;
		}
		if (preferredVoIncarnationAttributes.size() != 0 && selectedVo != null)
		{
			if (needEnter)
				sb.append("\n");
			sb.append("Selected VO: ").append(selectedVo).append(", its attribute values: ");
			outputAttrsMap(sb, preferredVoIncarnationAttributes);
			needEnter = true;			
		}
		if (xacmlAttributes.size() > 0) 
		{
			if (needEnter)
				sb.append("\n");
			sb.append("XACML authorization attributes: ");
			Iterator<Entry<String, List<XACMLAttribute>>> xacml = 
				xacmlAttributes.entrySet().iterator();
			while (xacml.hasNext())
			{
				Entry<String, List<XACMLAttribute>> validE = xacml.next();
				sb.append(validE.getValue());
			}
		}
		return sb.toString();
	}
}

/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import eu.unicore.security.util.PropertyMD.Type;

/**
 * Generates Asciidoc table with properties info
 * @author K. Benedyczak
 */
public class AsciidocFormater implements HelpFormatter
{
	@Override
	public String format(String pfx, Map<String, PropertyMD> metadata)
	{
		SortedSet<String> keys = new TreeSet<String>(metadata.keySet());
		if (keys.size() == 0)
			return "";
		StringBuilder ret = new StringBuilder();
		ret.append("[width=\"100%\",cols=\"<m,<,<,<\",frame=\"topbot\",options=\"header\"]\n");
		ret.append("|=====================================================================\n");
		ret.append("|Property name |Type |Default value / mandatory |Description \n");
		for (String key: keys)
		{
			PropertyMD md = metadata.get(key);
			ret.append("|" + pfx + key);
			if (md.getType() == Type.LIST)
				ret.append("*");
			ret.append(" |");
			ret.append(md.getTypeDecription() + " |");
			if (md.isMandatory())
				ret.append("_mandatory to be set_ |");
			else if (md.hasDefault())
				ret.append("`" + md.getDefault() +"` |");
			else
				ret.append("- |");
			String desc = md.getDescription();
			if (desc == null)
				desc = " ";
			ret.append(desc + " \n");
		}
		ret.append("|=====================================================================\n");
		return ret.toString();
	}

}

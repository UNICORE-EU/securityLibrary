/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.util.Map;

/**
 * Formats properties metadata to form reference information in some format, defined by implementation. 
 * @author K. Benedyczak
 */
public interface HelpFormatter
{
	public enum HelpFormat {asciidoc};
	
	public String format(String pfx, Map<String, PropertyMD> metadata);
}

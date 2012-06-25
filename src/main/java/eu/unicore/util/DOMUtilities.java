/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.util;

import java.io.IOException;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;

import eu.unicore.security.dsig.DigSignatureUtil;

/**
 * Utility methods to simply dump XML DOM. Useful for logging
 * e.g. when exact XML must be outputted (without any 'pretty printing').
 * @author golbi
 */
public class DOMUtilities
{
	public static String getDOMAsRawString(Document doc) throws IOException
	{
		return DigSignatureUtil.dumpDOMToString(doc);
	}

	public static void logDOMAsRawString(String prefix, Document doc, 
		Logger logger)
	{
		try
		{
			logger.trace(prefix + 
				getDOMAsRawString(doc));
		} catch (IOException e)
		{
			logger.warn("Can't serialize DOM to string: " + e);
		}
	}
}











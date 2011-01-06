/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.log4j.Logger;
import org.apache.xml.serialize.Method;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.w3c.dom.Document;

/**
 * Utility methods to simply dump XML DOM. Useful for logging
 * e.g. when exact XML must be outputted (without any 'pretty printing').
 * @author golbi
 */
public class DOMUtilities
{
	public static String getDOMAsRawString(Document doc) throws IOException
	{
		OutputFormat of = new OutputFormat(Method.XML, null, false);
		of.setPreserveSpace(true);
		of.setLineWidth(0);
		of.setPreserveEmptyAttributes(true);
		XMLSerializer serializer = new XMLSerializer(of);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		serializer.setOutputByteStream(baos);
		serializer.serialize(doc);
		return baos.toString();
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











/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 6, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.saml;

/**
 * Various SAML 2 constants.
 * @author K. Benedyczak
 */
public class SAMLConstants
{
	public static final String DN_FORMAT = 
		"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
	public static final String VERSION = "2.0";
	
	public static final String CONFIRMATION_SENDER_VOUCHES = 
		"urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";
	
	public static enum AuthNClasses {NONE, TLS};
	public static String AC_CLASS_TLS = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient";
}

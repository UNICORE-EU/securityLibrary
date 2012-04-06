/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

/**
 * This implementation of the SSL KeyManager can be used to create anonymous client-side 
 * SSL sockets, i.e. not authenticating. 
 * @author K. Benedyczak
 */
public class NoAuthKeyManager implements X509KeyManager
{
	@Override
	public String chooseClientAlias(String[] arg0, Principal[] arg1, Socket arg2)
	{
		return null;
	}

	@Override
	public String chooseServerAlias(String arg0, Principal[] arg1, Socket arg2)
	{
		return null;
	}

	@Override
	public X509Certificate[] getCertificateChain(String arg0)
	{
		return null;
	}

	@Override
	public String[] getClientAliases(String arg0, Principal[] arg1)
	{
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(String arg0)
	{
		return null;
	}

	@Override
	public String[] getServerAliases(String arg0, Principal[] arg1)
	{
		return null;
	}
}

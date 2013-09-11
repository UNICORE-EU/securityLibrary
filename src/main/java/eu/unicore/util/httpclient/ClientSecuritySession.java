/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.util.Date;

/**
 * Represents security session on the client side.
 * Stores the relevant information: id, scope, expiration time and the settings hash.
 * @author K. Benedyczak
 */
public class ClientSecuritySession
{
	private String sessionId;
	private String sessionHash;
	private String scope;
	private long expiryTS;
	
	
	public ClientSecuritySession(String sessionId, long expiryTS, String sessionHash, String scope)
	{
		this.sessionId = sessionId;
		this.expiryTS = expiryTS;
		this.sessionHash = sessionHash;
		this.scope = scope;
	}

	public String getSessionId()
	{
		return sessionId;
	}

	public String getSessionHash()
	{
		return sessionHash;
	}

	public long getExpiryTS()
	{
		return expiryTS;
	}

	public String getScope()
	{
		return scope;
	}
	
	public String toString()
	{
		return "Session for " + scope + ": " + sessionId + " expires " + new Date(expiryTS);
	}
}

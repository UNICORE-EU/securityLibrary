package eu.unicore.util.httpclient;

import java.util.Collection;

/**
 * Implementations are used to handle security sessions. Typically the default {@link SessionIDProviderImpl}
 * is the perfect choice.
 * @author K. Benedyczak
 */
public interface SessionIDProvider {
	
	/**
	 * Tries to find a session id for the given url and security settings. A session id is returned
	 * only if it is matching the URL container, session was established with the equivalent 
	 * settings and the session is not expired.
	 * @param url
	 * @param currentSettings
	 * @return session ID or null if no valid session ID exists
	 */
	public String getSessionID(String url, IClientConfiguration currentSettings);
	
	/**
	 * @return all known security sessions 
	 */
	public Collection<ClientSecuritySession> getAllSessions();

	/**
	 * Tries to find a session id for the given url and custom key. A session id is returned
	 * only if it is matching the URL container, session was established with the equivalent 
	 * key and the session is not expired.
	 * 
	 * @param url
	 * @param myKey
	 * @return session ID or null if no valid session ID exists
	 */
	public String getSessionID(String url, String myKey);
	
	/**
	 * Registers a new security session.
	 * @param sessionId
	 * @param url
	 * @param lifetime
	 * @param sessionsettings
	 */
	public void registerSession(String sessionId, String url, long lifetime, IClientConfiguration sessionsettings);
	
	/**
	 * Registers a new security session.
	 * @param sessionId
	 * @param url
	 * @param lifetime
	 * @param key
	 */
	public void registerSession(String sessionId, String url, long lifetime, String key);
	
	/**
	 * Adds a complete session, ready to be used
	 * @param session
	 */
	public void addSession(ClientSecuritySession session);
	
	/**
	 * Removes all sessions
	 */
	public void clearAll();
}

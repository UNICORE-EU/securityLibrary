package eu.unicore.util.httpclient;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.security.auth.x500.X500Principal;

import org.w3c.dom.Element;

import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.security.dsig.DigSignatureUtil;
import eu.unicore.security.etd.TrustDelegation;

/**
 * In-memory storage of security sessions. Thread safe. 
 * @author K. Benedyczak
 */
public class SessionIDProviderImpl implements SessionIDProvider {
	/**
	 * We expire sessions before their actual expiry timestamp,
	 * as each request needs some time to travel and there might be a clock difference.
	 */
	private static final long EXPIRY_BEFORE = 5*3600;
	private static final byte[] SEP = "||~~||".getBytes();
	
	private Map<String, ArrayList<ClientSecuritySession>> sessions;
	
	public SessionIDProviderImpl(){
		this.sessions = new HashMap<String, ArrayList<ClientSecuritySession>>();
	}

	/*
	 * extract the service independent part of a service URI
	 */
	public static String extractServerID(String uri){
		try{
			//TODO better way?
			String parts[] = uri.split("/services");
			if (parts.length > 1)
			{
				return parts[0]+"/services";
			}
			parts = uri.split("/rest");
			if (parts.length > 1)
			{
				return parts[0]+"/services";
			}
			return uri;
		}catch(Exception ex){
			return uri;
		}
	}

	@Override
	public synchronized String getSessionID(String url, IClientConfiguration currentSettings)
	{
		String scope = extractServerID(url);
		ArrayList<ClientSecuritySession> scoped = sessions.get(scope);
		if (scoped == null)
			return null;
		String sessionHash = checksumSecuritySettings(currentSettings);
		long currentTime = System.currentTimeMillis();
		for (int i=0; i<scoped.size(); i++)
		{
			ClientSecuritySession existing = scoped.get(i);
			
			if (currentTime > existing.getExpiryTS())
			{
				scoped.remove(i);
				i--;
				continue;
			}
			
			if (existing.getSessionHash().equals(sessionHash))
			{
				return existing.getSessionId();
			}
		}
		return null;
	}

	@Override
	public synchronized Collection<ClientSecuritySession> getAllSessions()
	{
		List<ClientSecuritySession> ret = new ArrayList<ClientSecuritySession>(sessions.size()*2);
		for (List<ClientSecuritySession> entry: sessions.values())
			ret.addAll(entry);
		return ret;
	}

	@Override
	public synchronized void clearAll()
	{
		sessions.clear();
	}

	@Override
	public synchronized void addSession(ClientSecuritySession session)
	{
		ArrayList<ClientSecuritySession> scoped = sessions.get(session.getScope());
		if (scoped == null)
		{
			scoped = new ArrayList<ClientSecuritySession>(5);
			sessions.put(session.getScope(), scoped);
		}
		scoped.add(session);
	}

	@Override
	public synchronized void registerSession(String sessionId, String url, long lifetime, 
			IClientConfiguration sessionSettings)
	{
		String scope = extractServerID(url);
		ArrayList<ClientSecuritySession> scoped = sessions.get(scope);
		if (scoped == null)
		{
			scoped = new ArrayList<ClientSecuritySession>(5);
			sessions.put(scope, scoped);
		}
		String sessionHash = checksumSecuritySettings(sessionSettings);
		
		boolean add = true;
		long expiry = lifetime+System.currentTimeMillis()-EXPIRY_BEFORE;
		for (int i=0; i<scoped.size(); i++)
		{
			ClientSecuritySession existing = scoped.get(i);
			if (existing.getSessionHash().equals(sessionHash))
			{
				if (existing.getExpiryTS() > expiry)
				{
					add = false;
					break;
				} else
				{
					scoped.remove(i);
					break;
				}
			}
		}
		
		if (add)
		{
			scoped.add(new ClientSecuritySession(sessionId, expiry, sessionHash, scope));
		}
	}
	
	/**
	 * Calculate a hash of security settings. This must allow to determine
	 * whether the settings have changed, so that a new security session is required.
	 * The following data is taken into account:
	 * <ol>
	 *  <li> caller's identity (DN)
	 *  <li> ETDs
	 *  <li> requested User
	 *  <li> preferences
	 *  <li> HTTP authn settings
	 *  <li> all extra tokens (what includes SAML attribute and authn assertions) 
	 * </ol>
	 *  
	 *  
	 * @return MD5 hash
	 */
	protected String checksumSecuritySettings(IClientConfiguration settings){
		byte[]res=null;
		try{
			MessageDigest md=MessageDigest.getInstance("MD5");
			// credential subject
			if (settings.getCredential() != null)
				md.update(safeToBytes(settings.getCredential().getSubjectName()));
			else
				md.update(safeToBytes(null));
			
			ETDClientSettings etd = settings.getETDSettings();
			//requested user
			md.update(safeToBytes(etd.getRequestedUser()));

			//base ETD chain
			List<TrustDelegation> baseChain = etd.getTrustDelegationTokens();
			if (baseChain != null)
			{
				for (TrustDelegation td: baseChain)
					md.update(safeToBytes(td.getXMLBeanDoc().xmlText()));
			} else
				md.update(safeToBytes(null));

			//TD target
			X500Principal receiver = etd.getReceiver();
			if (receiver != null)
				md.update(safeToBytes((receiver.getName())));
			else
				md.update(safeToBytes(null));
			
			//preferences
			Map<String,String[]>attrs=settings.getETDSettings().getRequestedUserAttributes2();
			SortedSet<String> sortedAttr = new TreeSet<String>(attrs.keySet());
			for(String k: sortedAttr){
				String val=Arrays.asList(attrs.get(k)).toString();
				md.update(safeToBytes(k));
				md.update(safeToBytes(val));
			}
			
			//HTTP auth
			md.update(safeToBytes(settings.getHttpUser()));
			md.update(safeToBytes(settings.getHttpPassword()));
			
			//Extra tokens including most notably SAML assertions, which we handle specially.
			//unknown objects have their hashcode used.
			Map<String, Object> extraTokens = settings.getExtraSecurityTokens();
			sortedAttr = new TreeSet<String>(extraTokens.keySet());
			for (String key: sortedAttr)
			{
				md.update(safeToBytes(key));
				Object val = extraTokens.get(key);
				
				if (val instanceof List)
				{
					List<?> someList = (List<?>) val;
					for (Object listEl: someList)
					{
						if (listEl instanceof Assertion)
						{
							String text = ((Assertion)listEl).getXMLBeanDoc().xmlText();
							md.update(safeToBytes(text));
						} else if (listEl instanceof Element)
						{
							String xml = DigSignatureUtil.dumpDOMToString((Element)listEl);
							md.update(safeToBytes(xml));
						} else if (listEl != null)
						{
							md.update(ByteBuffer.allocate(4).putInt(val.hashCode()).array());
						}
					}
				} else if (val != null) //this puts objects hashcode as byte array
					md.update(ByteBuffer.allocate(4).putInt(val.hashCode()).array());
			}
			
			res=md.digest();
		} catch(Exception ex)
		{
			throw new IllegalStateException("Can't calculate security session hash of the " +
					"client's configuration", ex);
		}
		return hexString(res);
	}
	
	
	private byte[] safeToBytes(String arg)
	{
		if (arg == null)
			return SEP;
		return (SEP+arg).getBytes();
	}
	
	private static String hexString(byte[] bytes){
		StringBuilder hexString = new StringBuilder();
		for (int i=0;i<bytes.length;i++) {
			String hex = Integer.toHexString(0xFF & bytes[i]); 
			if(hex.length()==1)hexString.append('0');
			hexString.append(hex);
		}
		return hexString.toString();
	}
}

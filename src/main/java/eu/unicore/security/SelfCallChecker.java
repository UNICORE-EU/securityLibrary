package eu.unicore.security;


/**
 * This simple interface is used to check whether the caller 
 * is the same as called service (i.e. it is self call). 
 * It is useful in trust delegation checking, as self calls are
 * always accepted as valid TD. Note that you can simply ignore
 * this feature. 
 * @author K. Benedyczak
 */
public interface SelfCallChecker
{
	/**
	 * Checks if the client is the same as the server which serves the request.
	 * @param client client's DN
	 * @return true if the above condition is true and the call should be accepted without further 
	 * delegation checking. 
	 */
	public boolean isSelfCall(String client);
}

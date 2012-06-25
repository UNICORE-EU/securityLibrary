/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 12, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security;
import java.security.cert.X509Certificate;

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
	 * @param client client's certificate
	 * @return true if the above contition is true and trust delegations
	 * should be accepted witout further checking in this request case.
	 */
	public boolean isSelfCall(X509Certificate client);
}

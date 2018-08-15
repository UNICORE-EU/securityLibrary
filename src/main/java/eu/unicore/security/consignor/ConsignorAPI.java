/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 7, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.consignor;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import eu.unicore.samly2.SAMLConstants.AuthNClasses;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.dsig.DSigException;

/**
 * @author K. Benedyczak
 */
public interface ConsignorAPI
{
	/**
	 * Generates signed consignor assertion. Used by gateway. 
	 * @param issuerDN issuer (usually gateway) DN
	 * @param consignorCert certificate of consignor
	 * @param pk issuer's private key
	 * @param negativeTolerance backwards validity in seconds form current time
	 * @param validity lifetime of assertion in seconds from current time
	 * @param acClass authentication context class choice (not implemented right now)
	 * @param ip clieent's IP address in dotted decimal form
	 * @return created assertion
	 * @throws DSigException if there are problems with signing assertion
	 */
	public ConsignorAssertion generateConsignorToken(
			String issuerDN, X509Certificate []consignorCert,
			PrivateKey pk, int negativeTolerance,
			int validity, AuthNClasses acClass, String ip)
			throws DSigException;

	/**
	 * Generates unsigned consignor assertion. Used by gateway. 
	 * @param issuerDN issuer (usually gateway) DN
	 * @param consignorCert certificate of consignor
	 * @param acClass authentication context class choice (not implemented right now)
	 * @param ip clieent's IP address in dotted decimal form
	 * @return created assertion
	 * @throws DSigException 
	 */
	public ConsignorAssertion generateConsignorToken(
			String issuerDN, X509Certificate []consignorCert,
			AuthNClasses acClass, String ip) throws DSigException;

	/**
	 * Generates signed consignor assertion without a subject. Used by gateway
	 * to state that connection is NOT AUTHENTICATED. 
	 * @param issuerDN issuer (usually gateway) DN
	 * @param negativeTolerance backwards validity in seconds form current time
	 * @param validity lifetime of assertion in seconds from current time
	 * @param pk issuer's private key
	 * @param ip client's IP address in dotted decimal form
	 * @return created assertion
	 * @throws DSigException if there are problems with signing assertion
	 */
	public ConsignorAssertion generateConsignorToken(
			String issuerDN, int negativeTolerance,
			int validity, PrivateKey pk, String ip)
			throws DSigException;

	/**
	 * Generates unsigned consignor assertion with an anonymous subject (without any confirmation). 
	 * Used by gateway to state that connection is NOT AUTHENTICATED. 
	 * @param issuerDN issuer (usually gateway) DN
	 * @return created assertion
	 */
	public ConsignorAssertion generateConsignorToken(String issuerDN);

	
	/**
	 * Checks if given assertion is valid with respect to given issuer.
	 * Note that signature is checked if and only if assertion is signed. 
	 * So if you want to be sure that assertion is valid AND signed use this method
	 * AND additionally check if assertion.isSigned().
	 * @param assertion to be checked
	 * @param issuerCertificate hypothetical issuer of this assertion. Warning:
	 * this certificate is not validated, so ensure that you provide a trusted certificate.
	 * @return result of verification
	 */
	public ValidationResult verifyConsignorToken(ConsignorAssertion assertion,
			X509Certificate issuerCertificate);

}
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

import eu.unicore.saml.SAMLConstants.AuthNClasses;
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
	 * @return created assertion
	 * @throws DSigException if there are problems with signing assertion
	 */
	public ConsignorAssertion generateConsignorToken(
			String issuerDN, X509Certificate []consignorCert,
			PrivateKey pk, int negativeTolerance,
			int validity, AuthNClasses acClass)
			throws DSigException;

	/**
	 * Generates unsigned consignor assertion. Used by gateway. 
	 * @param issuerDN issuer (usually gateway) DN
	 * @param consignorCert certificate of consignor
	 * @param acClass authentication context class choice (not implemented right now)
	 * @return created assertion
	 * @throws DSigException 
	 */
	public ConsignorAssertion generateConsignorToken(
			String issuerDN, X509Certificate []consignorCert,
			AuthNClasses acClass) throws DSigException;

	/**
	 * Generates signed consignor assertion without a subject. Used by gateway
	 * to state that connection is NOT AUTHENTICATED. 
	 * @param issuerDN issuer (usually gateway) DN
	 * @param consignorCert certificate of consignor
	 * @param pk issuer's private key
	 * @param negativeTolerance backwards validity in seconds form current time
	 * @param validity lifetime of assertion in seconds from current time
	 * @param acClass authentication context class choice (not implemented right now)
	 * @return created assertion
	 * @throws DSigException if there are problems with signing assertion
	 */
	public ConsignorAssertion generateConsignorToken(
			String issuerDN, int negativeTolerance,
			int validity, PrivateKey pk)
			throws DSigException;

	/**
	 * Generates unsigned consignor assertion without a subject. Used by gateway
	 * to state that connection is NOT AUTHENTICATED. 
	 * @param issuerDN issuer (usually gateway) DN
	 * @param consignorCert certificate of consignor
	 * @param acClass authentication context class choice (not implemented right now)
	 * @return created assertion
	 */
	public ConsignorAssertion generateConsignorToken(String issuerDN);

	
	/**
	 * Checks if given assertion is valid with respect to given issuer.
	 * Note that signature is checked if and only if assertion is signed. 
	 * So if you want to be sure that assertion is valid AND signed use this method
	 * AND additionaly check if assertion.isSigned().
	 * @param assertion to be checked
	 * @param issuerCertificate hypotetical issuer of this assertion
	 * @return result of verification
	 */
	public ValidationResult verifyConsignorToken(ConsignorAssertion assertion,
			X509Certificate issuerCertificate);

}
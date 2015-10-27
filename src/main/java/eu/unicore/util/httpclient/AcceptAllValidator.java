package eu.unicore.util.httpclient;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;

/**
 * sometimes it is useful to just accept all server certs
 * 
 * @author schuller
 */
public class AcceptAllValidator implements X509CertChainValidatorExt {

	@Override
	public ValidationResult validate(CertPath certPath) {
		return new ValidationResult(true);
	}

	@Override
	public ValidationResult validate(X509Certificate[] certChain) {
		return new ValidationResult(true);
	}

	@Override
	public X509Certificate[] getTrustedIssuers() {
		return null;
	}

	@Override
	public void addValidationListener(ValidationErrorListener listener) {}

	@Override
	public void removeValidationListener(ValidationErrorListener listener) {}

	@Override
	public void addUpdateListener(StoreUpdateListener listener) {}

	@Override
	public void removeUpdateListener(StoreUpdateListener listener) {}

	@Override
	public ProxySupport getProxySupport() {
		return null;
	}

	@Override
	public RevocationParameters getRevocationCheckingMode() {
		return null;
	}

	@Override
	public void dispose() {}

}

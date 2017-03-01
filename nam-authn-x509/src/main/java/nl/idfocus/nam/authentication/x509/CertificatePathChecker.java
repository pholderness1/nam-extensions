package nl.idfocus.nam.authentication.x509;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import com.novell.nidp.logging.NIDPLog;
import com.novell.nidp.resource.NIDPResourceManager;

public class CertificatePathChecker extends PKIXCertPathChecker
{
	private final String issuerName;
	private Logger logger;

	public CertificatePathChecker(String issuerName)
	{
		this.issuerName = issuerName;
		this.logger = NIDPLog.getAppLog();
	}

	@Override
	public void init(boolean forward) throws CertPathValidatorException
	{
		// TODO Auto-generated method stub
	}

	@Override
	public boolean isForwardCheckingSupported()
	{
		return false;
	}

	@Override
	public Set<String> getSupportedExtensions()
	{
		return null;
	}

	@Override
	public void check(Certificate cert, Collection<String> unresolvedCritExts)
			throws CertPathValidatorException
	{
		X509Certificate x509cert = (X509Certificate) cert;
		if (!unresolvedCritExts.isEmpty())
			throw new CertPathValidatorException(NIDPResourceManager.getInstance().getString(
					"NIDPLOGGING.200104051",
					NIDPResourceManager.SESSIONID_UNKNOWN,
					new String[] { unresolvedCritExts.toString(),
							x509cert.getSubjectDN().toString() }));
		// Check if RDW is the issuer of this certificate
		X500Principal issuer = x509cert.getIssuerX500Principal();
		logger.fine("Checking certificate issuer: " + issuer.getName());
		if (!issuerName.equals(issuer.getName()))
		{
			throw new CertPathValidatorException("Unsupported issuer '" + issuer.getName()
					+ "' for certificate with subject '" + x509cert.getSubjectDN().getName() + "'");
		}
	}

}

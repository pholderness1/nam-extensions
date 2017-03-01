package nl.idfocus.nam.authentication.x509;

import static org.junit.Assert.fail;

import java.io.File;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.novell.nidp.logging.NIDPLog;

import nl.idfocus.nam.util.MockNIDP;

public class TestCertificatePathChecker
{
	String rdwCert = "RDW Diensten - 31196.pem";
	String comodoCert = "Mark I. van Reijn.pem";

	@Before
	public void setUp() throws Exception
	{
		MockNIDP.initiateIDP();
		NIDPLog.createInstance();
	}

	@After
	public void tearDown() throws Exception
	{
		NIDPLog.destroyInstance();
	}

	@Test
	public void testSuccess() throws Exception
	{
		CertificatePathChecker checker = new CertificatePathChecker("CN=RDW Issuing CA 1,O=RDW,L=Groningen,C=NL");
		// Check RDW-issued cert
		X509Certificate x509cert = MockNIDP.getCertificate(getResourcePath(rdwCert));
		checker.check(x509cert, new ArrayList<String>());
	}

	@Test
	public void testFailure() throws Exception
	{
		CertificatePathChecker checker = new CertificatePathChecker("CN=RDW Issuing CA 1,O=RDW,L=Groningen,C=NL");
		// Check Comodo-issued cert
		X509Certificate x509cert = MockNIDP.getCertificate(getResourcePath(comodoCert));
		try
		{
			checker.check(x509cert, new ArrayList<String>());
			fail("Exception expected");
		}
		catch (CertPathValidatorException e) {}
	}

    private static String getResourcePath(String resourceName) throws Exception
    {
        File file = new File(TestCertificatePathChecker.class.getResource(resourceName).toURI());
        return file.getPath();
    }

}

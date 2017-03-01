package nl.idfocus.nam.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.StringReader;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Properties;

import org.apache.xerces.parsers.DOMParser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import com.novell.nidp.NIDPException;
import com.novell.nidp.authentication.AuthClassDefinition;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.xml.w3c.XMLException;
import com.novell.nidp.logging.NIDPLog;
import com.novell.nidp.saml2.SAML2MeDescriptor;
import com.novell.nidp.saml2.SAMLConstants;
import com.novell.nidp.saml2.protocol.SAML2AuthnResponse;
import com.novell.nidp.saml2.provider.SAML2MeServiceProvider;
import com.novell.nidp.saml2.provider.SAML2TrustedIdentityProvider;
import com.novell.nidp.saml2.provider.metadata.IDPSSODescriptor;

import nl.idfocus.nam.util.Base64;
import nl.idfocus.nam.util.MockNIDP;

public class TestIDPRedirect
{

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
	public void testDoAuthenticate() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = getDeaultProperties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "IDPRedirect", IDPRedirect.class.getName(), classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( "Other", newClass.getType() );
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "whatever");
        newClass.authenticate();
	}

	@Test
	public void testDecodeSAMLAssertion() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = getDeaultProperties();
		try 
		{
			AuthClassDefinition rawDefinition = new AuthClassDefinition( "IDPRedirect", IDPRedirect.class.getName(), classProps );
	        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
	        assertEquals( "Other", newClass.getType() );
	        // Try document creation
	        Document doc = (Document)callPrivateMethod(newClass, "getDocumentFromSAMLResponse", getFileContents("SamlResponseDigiD.b64"));
	        SAML2MeServiceProvider me = createMeProvider("demo.connectis.org-broker-digid");
	        SAML2AuthnResponse resp = new SAML2AuthnResponse(doc.getDocumentElement(), me, SAMLConstants.BINDING_POST, new Properties());
	        assertEquals( "The user cancelled.", resp.getStatus().getStatusMessage() );
		} 
		catch (XMLException | NIDPException e) 
		{
			fail(e.getClass().getName()+": "+e.getMessage());
		}
	}

	@Test
	public void testDecodeZippedSAMLRequest() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = new ArrayList<>();
		Properties classProps = getDeaultProperties();
		try 
		{
			AuthClassDefinition rawDefinition = new AuthClassDefinition( "IDPRedirect", IDPRedirect.class.getName(), classProps );
	        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
	        assertEquals( "Other", newClass.getType() );
	        // Try document creation
	        String zipped = getFileContents("SamlRequestPortaalZ.b64");
	        String notZipped = getFileContents("SamlRequestPortaalU.b64");
	        String doc = (String)callPrivateMethod(newClass, "inflateSAMLRequestIfNeeded", zipped);
	        assertEquals( notZipped, doc );
		} 
		catch (XMLException | NIDPException e) 
		{
			fail(e.getClass().getName()+": "+e.getMessage());
		}
	}

	@Test
	public void testDecodeNotZippedSAMLRequest() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = new ArrayList<>();
		Properties classProps = getDeaultProperties();
		try 
		{
			AuthClassDefinition rawDefinition = new AuthClassDefinition( "IDPRedirect", IDPRedirect.class.getName(), classProps );
	        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
	        assertEquals( "Other", newClass.getType() );
	        // Try document creation
	        String notZipped = getFileContents("SamlRequestPortaalU.b64");
	        String doc = (String)callPrivateMethod(newClass, "inflateSAMLRequestIfNeeded", notZipped);
	        assertEquals( notZipped, doc );
		} 
		catch (XMLException | NIDPException e) 
		{
			fail(e.getClass().getName()+": "+e.getMessage());
		}
	}

	private static Object callPrivateMethod(Object target, String methodName, Object... arguments ) throws Exception
	{
        Method method = target.getClass().getDeclaredMethod(methodName, arguments[0].getClass());
        method.setAccessible(true);
        Object result = method.invoke(target, arguments);
        return result;
	}

	private static SAML2MeServiceProvider createMeProvider(String... idpNames) throws Exception
	{
        SAML2MeServiceProvider me = new SAML2MeServiceProvider(new SAML2MeDescriptor(new Properties()));
        for(String idpName : idpNames)
        {
        	SAML2TrustedIdentityProvider idp = loadIdentityProvider(idpName);
        	me.addTrustedEntity(idp);
        }
        return me;
	}

	private static SAML2TrustedIdentityProvider loadIdentityProvider(String name) throws Exception
	{
        // create metadata XML element
        Document metadataDoc = getDocumentFromString(getFileContents(name+".xml"));
        Element metadata = (Element)metadataDoc.getElementsByTagName("md:IDPSSODescriptor").item(0);
        assertEquals("urn:oasis:names:tc:SAML:2.0:protocol", metadata.getAttribute("protocolSupportEnumeration"));
        IDPSSODescriptor sso = new IDPSSODescriptor(metadata, name, new Properties());
        return new SAML2TrustedIdentityProvider(sso);		
	}
	
	private static String getFileContents(String fileName) throws Exception
	{
        String filePath = getResourcePath(fileName);
		return new String( Files.readAllBytes(Paths.get(filePath)) );
	}

    private static String getResourcePath(String resourceName) throws Exception
    {
        File file = new File(TestIDPRedirect.class.getResource(resourceName).toURI());
        return file.getPath();
    }

	private static Document getDocumentFromString(String response) throws Exception
	{
		DOMParser parser = new DOMParser();
		parser.parse(new InputSource(new StringReader(response)));
		return parser.getDocument();
	}

	private static Document getDocumentFromBase64String(String response) throws Exception
	{
		String decodedResponse = new String(Base64.decode(response));
		return getDocumentFromString(decodedResponse);
	}

	private static Properties getDeaultProperties()
	{
		Properties classProps = new Properties();
		classProps.setProperty("Debug", "false");
		classProps.setProperty("IdpId", "digid");
		classProps.setProperty("CancelJSP", "digid-cancel");
		classProps.setProperty("IntermediateJSP", "digid");
		classProps.setProperty("ErrorJSP", "err");
		return classProps;
	}
}

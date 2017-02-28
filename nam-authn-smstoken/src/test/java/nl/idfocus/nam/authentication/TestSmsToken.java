package nl.idfocus.nam.authentication;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Properties;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.novell.nidp.authentication.AuthClassDefinition;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.logging.NIDPLog;

import nl.idfocus.nam.util.MockNIDP;
import nl.idfocus.nam.sms.BerichtenCentrumService;

public class TestSmsToken
{

	BerichtenCentrumService service;
	ArrayList<UserAuthority> m_UserStores;
	Properties classProps;
	AuthClassDefinition rawDefinition;

	@Before
	public void setUp() throws Exception
	{
		MockNIDP.initiateIDP();
		NIDPLog.createInstance();
		m_UserStores = MockNIDP.getAuthorities();
		classProps = getRandstadProperties();
		rawDefinition = new AuthClassDefinition( "SmsToken", "nl.idfocus.nam.authentication.SmsToken", classProps );
		service = BerichtenCentrumService.startNewSSLService(8081);
	}

	@After
	public void tearDown() throws Exception
	{
		NIDPLog.destroyInstance();
		service.shutdown();
	}

	@Test
	public void testInstantiateSmsToken() throws Exception
	{
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( AuthnConstants.TOKEN, newClass.getType() );
	}

	@Test
	public void testInitializeRequest() throws Exception
	{
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "whatever");
	}

	@Test
	public void testDoAuthenticateFail() throws Exception
	{
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), true, "returnurl");
        assertEquals( LocalAuthenticationClass.NOT_AUTHENTICATED, newClass.authenticate() );
	}

	@Test
	public void testDoAuthenticateShowPage() throws Exception
	{
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
		classProps.put("Principal", MockNIDP.getPrincipal() );
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), true, "returnurl");
        assertEquals( LocalAuthenticationClass.SHOW_JSP, newClass.authenticate() );
	}

	private Properties getRandstadProperties()
	{
		Properties props = new Properties();
		props.setProperty("DEBUG", "true");
//		props.setProperty("tokenLength", "");
//		props.setProperty("tokenCharacters", "");
		props.setProperty("smsProvider", "nl.rgn.sms.BerichtenCentrum");
		props.setProperty("mobileAttribute", "mobile");
		props.setProperty("mobileAltAttribute", "telephoneNumber");
		props.setProperty("expirationCookie", "rsgnlexpcookie");
		props.setProperty("expirationTime", "2");
		props.setProperty("expirationAttribute", "smsExpiration");
		props.setProperty("smsSendTimeout", "1000");
		props.setProperty("url", "https://localhost:8081/berichtencentrum/1/direct-sms");
		props.setProperty("applicationId", BerichtenCentrumService.APPLICATION_ID );
		props.setProperty("apiKey", BerichtenCentrumService.API_KEY );
		props.setProperty("senderAttribute", "company");
		props.setProperty("defaultSender", "12345");
		return props;
	}
}

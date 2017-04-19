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
import nl.idfocus.nam.sms.MessageBirdService;

public class TestSmsToken
{

	MessageBirdService service;
	ArrayList<UserAuthority> m_UserStores;
	Properties classProps;
	AuthClassDefinition rawDefinition;

	@Before
	public void setUp() throws Exception
	{
		MockNIDP.initiateIDP();
		NIDPLog.createInstance();
		m_UserStores = MockNIDP.getAuthorities();
		classProps = getMessageBirdProperties();
		rawDefinition = new AuthClassDefinition( "SmsToken", "nl.idfocus.nam.authentication.SmsToken", classProps );
		service = MessageBirdService.startNewSSLService(8081);
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

	@Test
	public void testDoAuthenticateLDAPScratchCode() throws Exception
	{
		classProps.put("scratchCodeType", "ldap");
		classProps.put("scratchCodeAttribute", "ldapScratchCode");
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
		classProps.put("Principal", MockNIDP.getPrincipal() );
		// Ensure second try
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "returnurl");
        assertEquals( LocalAuthenticationClass.AUTHENTICATED, newClass.authenticate() );
	}

	@Test
	public void testDoAuthenticateLDAPScratchCodeSameField() throws Exception
	{
		classProps.put("inputScratchcode", "Ecom_Token");
		classProps.put("scratchCodeType", "ldap");
		classProps.put("scratchCodeAttribute", "ldapScratchCode");
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
		classProps.put("Principal", MockNIDP.getPrincipal() );
		// Ensure second try
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "returnurl");
        assertEquals( LocalAuthenticationClass.AUTHENTICATED, newClass.authenticate() );
	}

	@Test
	public void testDoAuthenticateTOTPScratchCode() throws Exception
	{
		classProps.put("scratchCodeType", "totp");
		classProps.put("storeType", "PWM");
		classProps.put("SecretKeyAttribute", "totpSecretValuePam");
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
		classProps.put("Principal", MockNIDP.getPrincipal() );
		// Ensure second try
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "returnurl");
        assertEquals( LocalAuthenticationClass.AUTHENTICATED, newClass.authenticate() );
	}

	private Properties getMessageBirdProperties()
	{
		Properties props = new Properties();
		props.setProperty("DEBUG", "true");
		props.setProperty("smsProvider", "nl.idfocus.nam.sms.MessageBird");
		props.setProperty("url", "https://localhost:8081/api/sms");
		props.setProperty("userName", "myUserName" );
		props.setProperty("password", "myPassword" );
		props.setProperty("sender", "mySender");
		props.setProperty("reference", "myReference");
		props.setProperty("development", "true");
		return props;
	}
}

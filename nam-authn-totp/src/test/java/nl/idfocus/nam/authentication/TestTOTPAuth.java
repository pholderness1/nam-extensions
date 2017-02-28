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

import nl.idfocus.nam.totp.TOTPConstants;
import nl.idfocus.nam.totp.store.LdapStore;
import nl.idfocus.nam.util.MockNIDP;

public class TestTOTPAuth
{
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
		rawDefinition = new AuthClassDefinition( "TOTPAuth", "nl.idfocus.nam.authentication.TOTPAuth", classProps );
	}

	@After
	public void tearDown() throws Exception
	{
		NIDPLog.destroyInstance();
	}

	@Test
	public void testTOTPAuth() throws Exception
	{
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( AuthnConstants.TOKEN, newClass.getType() );
	}

	@Test
	public void testInitializeRequest() throws Exception
	{
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), true, "returnurl");
	}

	@Test
	public void testDoAuthenticate() throws Exception
	{
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
		classProps.put("Principal", MockNIDP.getPrincipal() );
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), true, "returnurl");
        assertEquals( LocalAuthenticationClass.SHOW_JSP, newClass.authenticate() );
	}

	@Test
	public void testDoAuthenticateUserName() throws Exception
	{
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
		classProps.put("Principal", MockNIDP.getPrincipal() );
		classProps.setProperty(TOTPConstants.PARAM_USER_NAME, "true");
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), true, "returnurl");
        assertEquals( LocalAuthenticationClass.SHOW_JSP, newClass.authenticate() );
	}

	@Test
	public void testDoAuthenticateFailNoPrincipal() throws Exception
	{
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), true, "returnurl");
        assertEquals( LocalAuthenticationClass.NOT_AUTHENTICATED, newClass.authenticate() );
	}

	private Properties getRandstadProperties()
	{
		Properties props = new Properties();
		props.setProperty("DEBUG", "true");
		props.setProperty(TOTPConstants.PARAM_ISSUER_NAME, "IDFocus");
		props.setProperty(TOTPConstants.PARAM_STORE_TYPE, TOTPConstants.STORE_LDAP);
		props.setProperty(TOTPConstants.PARAM_USER_NAME, "false");
		props.setProperty(TOTPConstants.PARAM_USER_NAME_ATTR, "cn");
		props.setProperty(LdapStore.PROP_ENCRYPTION_KEY, "mijnsleutel");
		props.setProperty(LdapStore.PROP_KEY_ATTRIBUTE_NAME, "totpSecretKey");
		props.setProperty(LdapStore.PROP_SCRATCH_ATTRIBUTE_NAME, "totpScratchCodes");
//		props.setProperty("", "");
		return props;
	}
}

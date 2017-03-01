package nl.idfocus.nam.authentication;

import static org.junit.Assert.assertEquals;

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

public class TestChainedAuth
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
	public void testChainedAuthOrMode() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = getOrModeProperties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "ChainedAuth", "nl.idfocus.nam.authentication.ChainedAuth", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( AuthnConstants.OTHER, newClass.getType() );
	}

	@Test
	public void testChainedAuthAndMode() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = getAndModeProperties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "ChainedAuth", "nl.idfocus.nam.authentication.ChainedAuth", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( AuthnConstants.OTHER, newClass.getType() );
	}

	@Test
	public void testInitializeRequest() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = getAndModeProperties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "ChainedAuth", "nl.idfocus.nam.authentication.ChainedAuth", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( AuthnConstants.OTHER, newClass.getType() );
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "whatever");
	}

	@Test
	public void testDoAuthenticateOrModeSuccess() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = getOrModeProperties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "ChainedAuth", "nl.idfocus.nam.authentication.ChainedAuth", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( AuthnConstants.OTHER, newClass.getType() );
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "whatever");
        assertEquals( LocalAuthenticationClass.AUTHENTICATED, newClass.authenticate() );
	}

	@Test
	public void testDoAuthenticateOrModeFail() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = getOrModeFailProperties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "ChainedAuth", "nl.idfocus.nam.authentication.ChainedAuth", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( AuthnConstants.OTHER, newClass.getType() );
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "whatever");
        assertEquals( LocalAuthenticationClass.NOT_AUTHENTICATED, newClass.authenticate() );
	}

	@Test
	public void testDoAuthenticateAndModeSuccess() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = getAndModeProperties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "ChainedAuth", "nl.idfocus.nam.authentication.ChainedAuth", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( AuthnConstants.OTHER, newClass.getType() );
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "whatever");
        assertEquals( LocalAuthenticationClass.AUTHENTICATED, newClass.authenticate() );
	}

	@Test
	public void testDoAuthenticateAndModeFail() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = getAndModeFailProperties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "ChainedAuth", "nl.idfocus.nam.authentication.ChainedAuth", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( AuthnConstants.OTHER, newClass.getType() );
        newClass.initializeRequest(MockNIDP.getRequest(), MockNIDP.getResponse(), MockNIDP.getIdpSession(), MockNIDP.getSessionData(), false, "whatever");
        assertEquals( LocalAuthenticationClass.NOT_AUTHENTICATED, newClass.authenticate() );
	}

	private Properties getOrModeProperties()
	{
		Properties props = new Properties();
		props.setProperty("DEBUG", "true");
		props.setProperty("MODE", "OR");
		props.setProperty("Class_0", Deny.class.getName());
		props.setProperty("Class_1", Allow.class.getName());
		props.setProperty("Class_1_AnonymousUserDn", "cn=mockito,ou=users,o=org");
		return props;
	}

	private Properties getOrModeFailProperties()
	{
		Properties props = new Properties();
		props.setProperty("DEBUG", "true");
		props.setProperty("MODE", "OR");
		props.setProperty("Class_0", Deny.class.getName());
		props.setProperty("Class_1", Deny.class.getName());
		return props;
	}

	private Properties getAndModeProperties()
	{
		Properties props = new Properties();
		props.setProperty("DEBUG", "true");
		props.setProperty("MODE", "AND");
		props.setProperty("Class_0", Allow.class.getName());
		props.setProperty("Class_0_AnonymousUserDn", "cn=mockito,ou=users,o=org");
		props.setProperty("Class_1", Allow.class.getName());
		props.setProperty("Class_1_AnonymousUserDn", "cn=mockito,ou=users,o=org");
		return props;
	}

	private Properties getAndModeFailProperties()
	{
		Properties props = new Properties();
		props.setProperty("DEBUG", "true");
		props.setProperty("MODE", "AND");
		props.setProperty("Class_0", Allow.class.getName());
		props.setProperty("Class_0_AnonymousUserDn", "cn=mockito,ou=users,o=org");
		props.setProperty("Class_1", Deny.class.getName());
		return props;
	}

}

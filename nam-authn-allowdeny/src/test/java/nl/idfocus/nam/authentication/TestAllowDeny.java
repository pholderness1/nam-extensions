package nl.idfocus.nam.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Properties;
import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.novell.nidp.NIDPException;
import com.novell.nidp.authentication.AuthClassDefinition;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPPrincipal;
import com.novell.nidp.common.authority.ldap.LdapGUID;
import com.novell.nidp.logging.NIDPLog;

import nl.idfocus.nam.util.MockNIDP;

public class TestAllowDeny {

	@Before
	public void setUp() throws Exception {
		MockNIDP.initiateIDP();
		NIDPLog.createInstance();
	}

	@After
	public void tearDown() throws Exception {
		NIDPLog.destroyInstance();
	}

	@Test
	public void testInstantiateAllow()
	{
		ArrayList<UserAuthority> m_UserStores = new ArrayList<>();
		Properties classProps = new Properties();
		classProps.setProperty("AnonymousUserDnDONTUSE", "cn=a,ou=b,o=c");
		try {
			AuthClassDefinition rawDefinition = new AuthClassDefinition( "Allow", "nl.idfocus.nam.authentication.Allow", classProps );
	        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
	        assertEquals( "Other", newClass.getType() );
		} catch (NIDPException e) {
			fail("NIDPException: "+e.getMessage());
		}
	}

	@Test
	public void testInstantiateAllowAnon()
	{
		ArrayList<UserAuthority> m_UserStores = new ArrayList<UserAuthority>();
		Properties classProps = new Properties();
		classProps.setProperty("AnonymousUserDn", "cn=a,ou=b,o=c");
		try {
			AuthClassDefinition rawDefinition = new AuthClassDefinition( "Allow", "nl.idfocus.nam.authentication.Allow", classProps );
	        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
	        assertEquals( "Other", newClass.getType() );
		} catch (NIDPException e) {
			fail("NIDPException: "+e.getMessage());
		}
	}

	@Test
	public void testAuthenticateAllow() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = new Properties();
		classProps.setProperty("AnonymousUserDnDONTUSE", "cn=a,ou=b,o=c");
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "Allow", "nl.idfocus.nam.authentication.Allow", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        int result = newClass.authenticate();
        assertEquals( LocalAuthenticationClass.AUTHENTICATED, result );
	}

	@Test
	public void testInstantiateDeny() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = new Properties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "Deny", "nl.idfocus.nam.authentication.Deny", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        assertEquals( "Other", newClass.getType() );
	}

	@Test
	public void testAuthenticateDeny() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		Properties classProps = new Properties();
		AuthClassDefinition rawDefinition = new AuthClassDefinition( "Deny", "nl.idfocus.nam.authentication.Deny", classProps );
        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, classProps);
        int result = newClass.authenticate();
        assertEquals( LocalAuthenticationClass.NOT_AUTHENTICATED, result );
	}

	@Test
	public void testLdapGUID() throws Exception
	{
		LdapGUID guid = createGuid();
		assertEquals(true, guid.getAsHexString().matches("[a-z0-9]+") );
	}

	@Test
	public void testLDAPPrincipal() throws Exception
	{
		ArrayList<UserAuthority> m_UserStores = MockNIDP.getAuthorities();
		LdapGUID guid = createGuid();

		LDAPPrincipal princ = new LDAPPrincipal(m_UserStores.get(0), guid.getAsHexString(), "cn="+guid.getAsHexString()+",o=bogus");
		princ.getAuthority();
	}

	private LdapGUID createGuid()
	{
		UUID uuid = UUID.randomUUID();
		ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
		bb.putLong(uuid.getMostSignificantBits());
		bb.putLong(uuid.getLeastSignificantBits());
		// Zonder '-' werkt het schijnbaar ook: "f788e013e90b48eb9e0a4037fab7fee7"
		return new LdapGUID(bb.array());
	}
}

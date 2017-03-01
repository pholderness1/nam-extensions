package nl.idfocus.nam.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Properties;

import nl.idfocus.nam.authentication.ChainedAuth;
import nl.idfocus.nam.authentication.TOTPOrSmsToken;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.novell.nam.common.ldap.jndi.JNDIUserStore;
import com.novell.nam.common.ldap.jndi.JNDIUserStoreManager;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPUserAuthority;

public class TestKrbFallback 
{
	private Properties allProps;
	private Properties chainProps;
	private Properties totpProps;
	private ArrayList<UserAuthority> allStores;

	@Before
	public void setUp() throws Exception 
	{
		allProps = new Properties();
		chainProps = new Properties();
		totpProps = new Properties();
		allProps.put( "DEBUG", "true" );
		allProps.put( "MainJSP", "true" );
		allProps.put( "JSP", "login" );
		allStores = new ArrayList<UserAuthority>();
		UserAuthority ua = new LDAPUserAuthority( new JNDIUserStore( new JNDIUserStoreManager(), "bogus", "Bogus", "admin", "password", 1));
		allStores.add(ua);
	}

	@After
	public void tearDown() throws Exception 
	{
	}

	@Test
	public void testChainedAuth() 
	{
		chainProps.putAll(allProps);
		chainProps.put("Class_1", "ProtectedPasswordClass");
		chainProps.put("Class_1_JSP", "plogin");
		chainProps.put("Class_2", "nl.idfocus.nam.authentication.BOFH");
		chainProps.put("Class_2_JSP", "blogin");
		try
		{
			ChainedAuth auth = new ChainedAuth( chainProps, allStores );
			assertEquals( AuthnConstants.OTHER, auth.getType() );
		}
		catch (Exception e)
		{
			fail("Exception during instantiation: "+e.getMessage());
		}
	}

	@Test
	public void testTOTPOrSmsToken() 
	{
		totpProps.putAll(allProps);
		totpProps.put( "sms_smsSendTimeout", "15000" );
		totpProps.put( "sms_JSP", "slogin" );
		totpProps.put( "sms_userName", "uname" );
		totpProps.put( "sms_password", "pwd" );
		totpProps.put( "sms_sender", "sender" );
		totpProps.put( "totp_JSP", "tlogin" );
		try
		{
			TOTPOrSmsToken auth = new TOTPOrSmsToken( totpProps, allStores );
			assertEquals( AuthnConstants.TOKEN, auth.getType() );
		}
		catch (Exception e)
		{
			fail("Exception during instantiation: "+e.getMessage());
		}
	}
}

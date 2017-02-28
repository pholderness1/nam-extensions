package nl.idfocus.nam.totp;

import static org.junit.Assert.*;

import java.util.Properties;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import nl.idfocus.nam.totp.Authenticator;
import nl.idfocus.nam.totp.UserRegistration;

public class TestUserRegistration
{

	@Before
	public void setUp() throws Exception
	{
	}

	@After
	public void tearDown() throws Exception
	{
	}

	@Test
	public void testUserRegistration() throws Exception
	{
		Properties props = new Properties();
		UserRegistration reg = new UserRegistration(props);
		assertEquals("IDFocus", reg.getOrgName());
	}

	@Test
	public void testGetSecretKey()
	{
		Properties props = new Properties();
		UserRegistration reg = new UserRegistration(props);
		assertEquals(16, reg.getSecretKey().length());
	}

	@Test
	public void testGetScratchCodes()
	{
		Properties props = new Properties();
		UserRegistration reg = new UserRegistration(props);
		assertEquals(5, reg.getScratchCodes().size());
		assertEquals(8, reg.getScratchCodes().get(0).toString().length());
	}

	@Test
	public void testValidateScratchCode() throws Exception
	{
		Properties props = new Properties();
		UserRegistration reg = new UserRegistration(props);
		int scratchCode1 = reg.getScratchCodes().get(0);
		int scratchCode2 = reg.getScratchCodes().get(1);
		Authenticator auth = new Authenticator(props, reg);
		assertEquals( true, auth.validateScratchCode(scratchCode1) );
		assertEquals( 4,  reg.getScratchCodes().size());
		assertEquals( false, auth.validateScratchCode(scratchCode1) );
		assertEquals( true, auth.validateScratchCode(scratchCode2) );
		assertEquals( 3,  reg.getScratchCodes().size());
	}
}

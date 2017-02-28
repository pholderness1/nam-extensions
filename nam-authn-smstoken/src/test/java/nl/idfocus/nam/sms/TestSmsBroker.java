package nl.idfocus.nam.sms;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import nl.idfocus.nam.sms.SmsConfig;
import nl.idfocus.nam.sms.SmsProvider;
import nl.rgn.sms.SmsBroker;

public class TestSmsBroker 
{
	SmsConfig config = new SmsConfig();

	@Before
	public void setUp() throws Exception 
	{
		config = new SmsConfig();
		config.addParam( "url", "http://test.bogus" );
		config.addParam( "internalOeNumber", "context" );
		config.addParam( "internalOeNumberDefault", "1365" );
		config.addParam( "application", "IDMS" );
		config.addParam( "custom", "IDMS" );
		config.addParam( "timeToLive", "7200" );
	}

	@After
	public void tearDown() throws Exception 
	{
	}

	@Test
	public void testSendFailure() throws Exception
	{
		SmsProvider rsg = new SmsBroker();
		rsg.init(config, true);
		config.addParam( SmsConfig.PRINCIPAL_DN, "cn=mark,o=asd" );
		config.addParam( "internalOeNumber", null );
		rsg.update(config);
		assertEquals( false, rsg.send( "test", "0641707287", 1000 ) );
	}

	@Test
	public void testInitialize() throws Exception
	{
		SmsProvider rsg = new SmsBroker();
		assertEquals( false, rsg.ready() );
		rsg.init(config, true);
		assertEquals( true, rsg.ready() );
	}

	@Test
	public void testGetName() throws Exception
	{
		SmsProvider rsg = new SmsBroker();
		assertEquals( "Randstad Groep NL SMS Broker", rsg.getName() );
	}

	@Test
	public void testGetParameters() throws Exception
	{
		SmsProvider rsg = new SmsBroker();
		assertEquals( 6, rsg.getParameters().length );
		assertEquals( "url", rsg.getParameters()[0].getName() );
	}

}

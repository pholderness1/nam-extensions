package nl.idfocus.nam.sms;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import nl.idfocus.nam.sms.SmsConfig;
import nl.idfocus.nam.sms.SmsParameterDesc;
import nl.idfocus.nam.sms.SmsProvider;
import nl.rgn.sms.BerichtenCentrum;

public class TestBerichtenCentrum 
{
	SmsConfig config;
	SmsProvider provider;
	BerichtenCentrumService service;

	@Before
	public void setUp() throws Exception 
	{
		service = BerichtenCentrumService.startNewSSLService(8081);
		provider = new BerichtenCentrum();
		config = new SmsConfig();
		config.addParam( BerichtenCentrum.PARAM_URL, "https://localhost:8081/berichtencentrum/1/direct-sms" );
		config.addParam( BerichtenCentrum.PARAM_DEFAULT_SENDER, "rnl" );
		config.addParam( BerichtenCentrum.PARAM_APP_ID, BerichtenCentrumService.APPLICATION_ID );
		config.addParam( BerichtenCentrum.PARAM_API_KEY, BerichtenCentrumService.API_KEY );
	}

	@After
	public void tearDown() throws Exception 
	{
		service.shutdown();
	}

	@Test
	public void testInit() 
	{
		assertEquals( false, provider.ready() );
		provider.init(config, true);
		assertEquals( "Not ready: ", true, provider.ready() );
		assertEquals(false, provider.needPrincipal());
	}

	@Test
	public void testSendSuccessDefaultCompany() throws Exception
	{
		provider.init(config, true);
		assertEquals( true, provider.send( "test", "0641707287", 1000 ) );
	}

	@Test
	public void testSendSuccess() throws Exception
	{
		provider.init(config, true);
		config.addParam( "senderAttribute", "ygn" );
		provider.update(config);
		assertEquals( true, provider.send( "test", "0641707287", 1000 ) );
	}

	@Test
	public void testSendFailure() throws Exception
	{
		config.addParam( BerichtenCentrum.PARAM_APP_ID, "My API" );
		config.addParam( BerichtenCentrum.PARAM_API_KEY, "abcd-efgh-ijkl" );
		provider.init(config, true);
		config.addParam( "senderAttribute", "ttg" );
		provider.update(config);
		assertEquals( false, provider.send( "test", "0641707287", 1000 ) );
	}

	@Test
	public void testGetName() throws Exception
	{
		assertEquals( "Randstad Groep NL Berichtencentrum", provider.getName() );
	}

	@Test
	public void testGetParameters() throws Exception
	{
		SmsParameterDesc[] params = provider.getParameters();
		assertEquals( 4, params.length );
	}

}

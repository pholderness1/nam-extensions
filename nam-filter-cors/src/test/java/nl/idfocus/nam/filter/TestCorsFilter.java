package nl.idfocus.nam.filter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import javax.servlet.FilterConfig;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class TestCorsFilter
{
	private FilterConfig filterConfig;
	private CorsFilter filter;

	@Before
	public void setUp() throws Exception
	{
		filter = new CorsFilter();
		filterConfig = MockFilter.getPopulatedFilterConfig();
	}

	@After
	public void tearDown() throws Exception
	{
	}

	@Test
	public void testInitDefaults() throws Exception
	{
		filter.init(MockFilter.getDefaultFilterConfig());
		assertEquals(true, filter.isAnyOriginAllowed());
		assertEquals(true,filter.isSupportsCredentials());
	}

	@Test
	public void testInitSettings() throws Exception
	{
		filter.init(filterConfig);
		assertEquals(false, filter.isAnyOriginAllowed());
		assertEquals(false,filter.isSupportsCredentials());
	}

	@Test
	public void testIsIDFOriginAllowed() throws Exception
	{
		filter.init(filterConfig);
		assertEquals(true,filter.isOriginAllowed("http://www.idfocus.nl"));
		assertEquals(true,filter.isOriginAllowed("http://iets.idfocus.nl"));
		assertEquals(false,filter.isOriginAllowed("https://www.idfocus.nl"));
	}

	@Test
	public void testIsMobiOriginAllowed() throws Exception
	{
		filter.init(filterConfig);
		assertEquals(false,filter.isOriginAllowed("http://www.mobi-id.nl"));
		assertEquals(false,filter.isOriginAllowed("http://iets.mobi-id.nl"));
		assertEquals(true,filter.isOriginAllowed("https://www.mobi-id.nl"));
		assertEquals(true,filter.isOriginAllowed("https://iets.mobi-id.nl"));
	}

	@Test
	public void testIsValidOrigin() throws Exception
	{
		assertEquals(true,CorsFilter.isValidOrigin("http://www.idfocus.nl"));
	}

	@Test
	public void testIsAnyOriginAllowed() throws Exception
	{
		filter.init(filterConfig);
		assertEquals(false,filter.isAnyOriginAllowed());
	}

	@Test
	@Ignore
	public void testGetExposedHeaders() throws Exception
	{
		filter.init(filterConfig);
		fail("Not yet implemented");
	}

	@Test
	@Ignore
	public void testIsSupportsCredentials() throws Exception
	{
		filter.init(filterConfig);
		fail("Not yet implemented");
	}

	@Test
	@Ignore
	public void testGetPreflightMaxAge() throws Exception
	{
		filter.init(filterConfig);
		fail("Not yet implemented");
	}

	@Test
	@Ignore
	public void testGetAllowedOrigins() throws Exception
	{
		filter.init(filterConfig);
		fail("Not yet implemented");
	}

	@Test
	@Ignore
	public void testGetAllowedHttpMethods() throws Exception
	{
		filter.init(filterConfig);
		fail("Not yet implemented");
	}

	@Test
	@Ignore
	public void testGetAllowedHttpHeaders() throws Exception
	{
		filter.init(filterConfig);
		fail("Not yet implemented");
	}

	@Test
	@Ignore
	public void testDoFilter() throws Exception
	{
		filter.init(filterConfig);
		fail("Not yet implemented");
	}
}

package nl.idfocus.nam.filter;

import static org.junit.Assert.*;

import java.util.Enumeration;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;

import org.junit.After;
import org.junit.Before;
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
	public void testIsOriginAllowed() throws Exception
	{
		filter.init(filterConfig);
		assertEquals(true,filter.isOriginAllowed("http://www.idfocus.nl"));
	}

	@Test
	public void testIsValidOrigin() throws Exception
	{
		assertEquals(true,CorsFilter.isValidOrigin("http://www.idfocus.nl"));
	}

	@Test
	public void testIsAnyOriginAllowed() throws Exception
	{
		fail("Not yet implemented");
	}

	@Test
	public void testGetExposedHeaders() throws Exception
	{
		fail("Not yet implemented");
	}

	@Test
	public void testIsSupportsCredentials() throws Exception
	{
		fail("Not yet implemented");
	}

	@Test
	public void testGetPreflightMaxAge() throws Exception
	{
		fail("Not yet implemented");
	}

	@Test
	public void testGetAllowedOrigins() throws Exception
	{
		fail("Not yet implemented");
	}

	@Test
	public void testGetAllowedHttpMethods() throws Exception
	{
		fail("Not yet implemented");
	}

	@Test
	public void testGetAllowedHttpHeaders() throws Exception
	{
		fail("Not yet implemented");
	}

	@Test
	public void testDoFilter() throws Exception
	{
		fail("Not yet implemented");
	}
}

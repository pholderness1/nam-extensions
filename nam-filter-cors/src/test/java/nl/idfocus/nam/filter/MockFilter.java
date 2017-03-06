package nl.idfocus.nam.filter;

import static org.mockito.Mockito.mock;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MockFilter
{

	private MockFilter()
	{
		// No instantiation
	}

	public static FilterConfig getDefaultFilterConfig()
	{
		return new MockFilterConfig(false);
	}

	public static FilterConfig getPopulatedFilterConfig()
	{
		return new MockFilterConfig(true);
	}

	public static HttpServletResponse getResponse()
	{
		return mock(HttpServletResponse.class);
	}

	public static ServletRequest getRequest()
	{
		return mock(ServletRequest.class);
	}

	public static FilterChain getFilterChain()
	{
		return mock(FilterChain.class);
	}
}

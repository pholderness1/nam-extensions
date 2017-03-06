package nl.idfocus.nam.filter;

import static org.mockito.Mockito.mock;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;

public class MockFilterConfig implements FilterConfig
{
	Map<String,String> params;

	public MockFilterConfig(boolean populate)
	{
		params = new HashMap<>();
		if (populate)
			populateParameters();
	}

	@Override
	public String getFilterName()
	{
		return "CORS Wildcard Filter";
	}

	@Override
	public String getInitParameter(String paramName)
	{
		if(params.containsKey(paramName))
			return params.get(paramName);
		return null;
	}

	@Override
	public Enumeration<String> getInitParameterNames()
	{
		if(params.isEmpty())
			return null;
		return new Vector<String>(params.keySet()).elements();
	}

	@Override
	public ServletContext getServletContext()
	{
		return mock(ServletContext.class);
	}

	private void populateParameters()
	{
		params.put(CorsFilter.PARAM_CORS_ALLOWED_HEADERS, "Accept");
		params.put(CorsFilter.PARAM_CORS_ALLOWED_METHODS, "GET,POST");
		params.put(CorsFilter.PARAM_CORS_ALLOWED_ORIGINS, "http://*.idfocus.nl,https://*.mobi-id.nl");
		params.put(CorsFilter.PARAM_CORS_EXPOSED_HEADERS, "Accept");
		params.put(CorsFilter.PARAM_CORS_PREFLIGHT_MAXAGE, "1000");
		params.put(CorsFilter.PARAM_CORS_REQUEST_DECORATE, "true");
		params.put(CorsFilter.PARAM_CORS_SUPPORT_CREDENTIALS, "false");
	}
}

package nl.idfocus.nam.kerberos;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import nl.idfocus.nam.util.LogFormatter;

/**
 * Servlet Filter implementation class KrbFallbackFilter
 */
public class KrbFallbackFilter implements Filter
{
	private static final Logger	logger			= LogFormatter
			.getConsoleLogger(KrbFallbackFilter.class.getName());

	private static final String	ATTR_TAGGED		= "krbtagged";
	private static final String	ATTR_FALLBACK	= "fallbackmethod";
	private static final String	HDR_AUTH		= "Authorization";
	private static final String	SEPARATOR		= ",";

	private List<String>		contractId;
	private List<String>		contractUri;

	/**
	 * Default constructor.
	 */
	public KrbFallbackFilter()
	{
		logger.info("Instantiating Kerberos Fallback Filter");
		contractId = null;
		contractUri = null;
	}

	/**
	 * @see Filter#init(FilterConfig)
	 */
	public void init(FilterConfig fConfig) throws ServletException
	{
		logger.info("Initializing Kerberos Fallback Filter");
		// Check for contract identifier parameters
		contractId = getInitParameter(fConfig.getInitParameter("contract-id"));
		contractUri = getInitParameter(fConfig.getInitParameter("contract-uri"));
		if (contractId.size() == 0 && contractUri.size() == 0)
			logger.info("Matching on all URLs");
		else
			logger.info("Matching on "
					+ Arrays.toString(contractId.toArray(new String[contractId.size()])) + " and "
					+ Arrays.toString(contractUri.toArray(new String[contractUri.size()])));
	}

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException
	{
		logger.info("Kerberos Fallback Filter: filtering");
		if (isMatch((HttpServletRequest) request))
		{
			logger.info("Kerberos Fallback Filter: request matches");
			// Get http session object
			HttpSession session = ((HttpServletRequest) request).getSession();
			// Check for previous tag
			if (isTagged(session))
			{
				// Force fallback if needed
				if (lacksAuthHeader((HttpServletRequest) request))
				{
					logger.info("Kerberos Fallback Filter: forcing fallback");
					session.setAttribute(ATTR_FALLBACK, "true");
				}
				else
				{
					// Remove tag
					logger.info("Kerberos Fallback Filter: untagging session");
					session.removeAttribute(ATTR_TAGGED);
				}
			}
			else
			{
				logger.info("Kerberos Fallback Filter: tagging session");
				session.setAttribute(ATTR_TAGGED, "true");
			}
		}
		// pass the request along the filter chain
		chain.doFilter(request, response);
	}

	private boolean isMatch(HttpServletRequest request)
	{
		if (contractId.size() == 0 && contractUri.size() == 0)
			return true;
		String curi = request.getParameter("AuthnContextStatementRef");
		if (curi != null && contractUri.contains(curi.toLowerCase()))
			return true;
		String cid = request.getParameter("id");
		if (cid != null && contractId.contains(cid.toLowerCase()))
			return true;
		return false;
	}

	private boolean lacksAuthHeader(HttpServletRequest request)
	{
		if (request.getHeader(HDR_AUTH) == null)
			return true;
		return false;
	}

	private boolean isTagged(HttpSession session)
	{
		if (session.getAttribute(ATTR_TAGGED) != null)
			return true;
		return false;
	}

	private List<String> getInitParameter(String param)
	{
		List<String> result = new ArrayList<String>();
		if (param != null)
		{
			if (param.contains(SEPARATOR))
			{
				String[] values = param.split(SEPARATOR);
				for (String value : values)
					result.add(value.trim().toLowerCase());
			}
			else
			{
				result.add(param);
			}
		}
		return result;
	}

	/**
	 * @see Filter#destroy()
	 */
	public void destroy()
	{
		// TODO Auto-generated method stub
	}

}

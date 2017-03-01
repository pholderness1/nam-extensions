package nl.idfocus.nam.authentication;

import java.util.ArrayList;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.novell.nidp.NIDPSession;
import com.novell.nidp.NIDPSessionData;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;

public class KrbForceFallback extends LocalAuthenticationClass
{
	private static final String	ATTR_TAGGED		= "krbtagged";
	private static final String	ATTR_FALLBACK	= "fallbackmethod";
	private static final String	HDR_AUTH		= "Authorization";

	public KrbForceFallback(Properties props, ArrayList<UserAuthority> stores)
	{
		super(props, stores);
	}

	@Override
	public void initializeRequest(HttpServletRequest request, HttpServletResponse response,
			NIDPSession idpSession, NIDPSessionData sessionData, boolean firstCall, String returnUrl)
	{
		// Call super
		super.initializeRequest(request, response, idpSession, sessionData, firstCall, returnUrl);
		// Get http session object
		HttpSession httpSession = ((HttpServletRequest) request).getSession();
		// Check for session tag
		if (isTagged(httpSession))
		{
			if (lacksAuthHeader(request))
			{
				// Force fallback
				request.getSession().setAttribute(ATTR_FALLBACK, true);
			}
		}
		else
		{
			request.getSession().setAttribute(ATTR_TAGGED, true);
		}
	}

	@Override
	public int authenticate()
	{
		// TODO check if this is enough
		return AUTHENTICATED;
	}

	private boolean isTagged(HttpSession session)
	{
		if (session.getAttribute(ATTR_TAGGED) != null)
			return true;
		return false;
	}

	private boolean lacksAuthHeader(HttpServletRequest request)
	{
		if (request.getHeader(HDR_AUTH) == null)
			return true;
		return false;
	}

}

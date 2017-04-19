package nl.idfocus.nam.authentication;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.servlet.http.HttpServletRequest;

import org.apache.xerces.parsers.DOMParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.novell.nidp.NIDPConstants;
import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.authentication.local.PageToShow;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.protocol.AuthnRequest;
import com.novell.nidp.common.provider.MeDescriptor;
import com.novell.nidp.common.provider.MeProvider;
import com.novell.nidp.common.xml.w3c.XMLException;
import com.novell.nidp.logging.NIDPLog;
import com.novell.nidp.saml2.SAMLConstants;
import com.novell.nidp.saml2.protocol.SAML2AuthnResponse;
import com.novell.nidp.saml2.protocol.SAML2PConstants;
import com.novell.nidp.saml2.protocol.SAML2Status;
import com.novell.nidp.saml2.protocol.SAML2StatusCode;

import nl.idfocus.nam.util.Base64;
import nl.idfocus.nam.util.ExistingPrincipalResolver;
import nl.idfocus.nam.util.ParameterDebugger;

/**
 * Authentication class for NetIQ Access Manager 4.x that allows immediate
 * redirection to an external IDP.
 * 
 * @author mvreijn@idfocus.nl
 *
 */
public class IDPRedirect extends LocalAuthenticationClass
{
	public static final String	IDP_ID_TAG					= "idptag";
	public static final String	SID_TAG						= "sidtag";
	public static final String	CANCEL_TAG					= "canceltag";

	private static final String	NIDP_URL_ROOT				= "nidp";
	private static final String	NIDP_URL_SEND				= "spsend";
	private static final String	NIDP_URL_SID				= "sid";
	private static final String	NIDP_URL_ID					= "id";
	private static final String	URL_SEPARATOR				= "/";
	private static final String	PROPERTY_DEBUG				= "Debug";
	private static final String	PROPERTY_IDP_ID				= "IdpId";
	private static final String	PROPERTY_IDP_HANDLER		= "Protocol";
	private static final String	PROPERTY_CANCEL_PAGE		= "CancelJSP";
	private static final String	PROPERTY_INTERMEDIATE_PAGE	= "IntermediateJSP";
	private static final String	PROPERTY_ERROR_PAGE			= "ErrorJSP";
	private static final String	CANCEL_MESSAGE				= "The user cancelled.";
	private boolean				compareExactCancelMessage	= true;
	private final Logger		logger						= NIDPLog.getAppLog();
	private String				idpID;
	private String				protocolHandler;
	private String				intermediatePage;
	private String				errorPage;
	private String				cancelPage;
	private boolean				debugMode;

	private static final String PKGBUILD = IDPRedirect.class.getPackage().getImplementationVersion();

	public IDPRedirect(Properties props, ArrayList<UserAuthority> stores)
	{
		super(props, stores);
		logger.log( Level.INFO, "IDP Redirect Authentication Class build "+PKGBUILD+" (c) IDFocus B.V. <info@idfocus.nl>" );
		idpID = props.getProperty(PROPERTY_IDP_ID);
		protocolHandler = props.getProperty(PROPERTY_IDP_HANDLER, "saml2");
		debugMode = Boolean.parseBoolean(props.getProperty(PROPERTY_DEBUG, "false"));
		intermediatePage = props.getProperty(PROPERTY_INTERMEDIATE_PAGE);
		errorPage = props.getProperty(PROPERTY_ERROR_PAGE);
		cancelPage = props.getProperty(PROPERTY_CANCEL_PAGE, errorPage);
	}

	@Override
	public String getType()
	{
		return AuthnConstants.OTHER;
	}

	@Override
	protected int doAuthenticate()
	{
		if (debugMode)
		{
			ParameterDebugger debugger = ParameterDebugger.getDebugger(logger);
			debugger.showSession(m_Request.getSession());
			debugger.showAttributes(m_Request);
			debugger.showParameters(m_Request.getParameterMap());
		}
		logger.log(Level.INFO, "Checking for previous authentication");
		NIDPPrincipal currentPrincipal = ExistingPrincipalResolver.resolveUserPrincipal(this,
				m_Properties, m_Session);
		if (isFirstCallAfterPrevMethod())
		{
			logger.log(Level.INFO, "Start authentication, redirecting to " + idpID);
			return startAuthenticationProcess();
		}
		else if (currentPrincipal == null)
		{
			return handleUnsuccessfulResponse();
		}
		logger.log(Level.INFO, "A principal has been logged in");
		setPrincipal(currentPrincipal);
		return AUTHENTICATED;
	}

	private int handleUnsuccessfulResponse()
	{
		if (hasSAMLResponse())
		{
			if (isCancelMessage())
			{
				logger.log(Level.SEVERE, "Cancel requested by user.");
				tagSessionAsCancelled();
				invalidateUserSession();
				return showCancelPage();
			}
			logger.log(Level.SEVERE,
					"No principal created from SAML response, assuming authentication failed.");
			return technicalFailureOccurred();
		}
		logger.log(Level.INFO, "No principal found, redirecting to " + idpID);
		return startAuthenticationProcess();
	}

	private void invalidateUserSession()
	{
		AuthnRequest areq = this.m_SessionData.getAuthnRequestToIDP();
		try
		{
			String parmValue = areq.toString();
			this.logger.log(Level.FINE, String.format("SAML request %s has value %s.",
					SAMLConstants.PARM_REQUEST, parmValue));
		}
		catch (Exception e)
		{
			this.logger.log(Level.FINE, "Exception during AuthnRequest processing", e);
		}
		this.m_Session.reset();
		this.m_Request.getSession().invalidate();
	}

	private boolean hasSAMLResponse()
	{
		String response = m_Request.getParameter(SAMLConstants.PARM_RESPONSE);
		if (response != null)
			return true;
		return false;
	}

	private boolean hasSAMLRequest()
	{
		String response = m_Request.getParameter(SAMLConstants.PARM_REQUEST);
		if (response != null)
			return true;
		return false;
	}

	private boolean isCancelMessage()
	{
		try
		{
			SAML2Status status = getAuthenticationStatus();
			String statusMessage = status.getStatusMessage();
			logger.log(Level.FINE, "Status Message: " + statusMessage);
			SAML2StatusCode code = status.getStatusCode();
			if (SAML2PConstants.STATUS_RESPONDER.equals(code.getTopLevelStatus())
					&& SAML2PConstants.STATUS_AUTHNFAILED.equals(code.getSecondLevelStatus())
					&& (!compareExactCancelMessage
							|| CANCEL_MESSAGE.equalsIgnoreCase(statusMessage)))
			{
				return true;
			}
		}
		catch (NIDPException e)
		{
			logger.log(Level.WARNING, "Failed to parse SAML Response: " + e.getMessage(), e);
		}
		return false;
	}

	private SAML2Status getAuthenticationStatus() throws NIDPException
	{
		SAML2AuthnResponse samlResponse = getAuthenticationResponse(m_Request);
		logger.log(Level.FINER, "SAML Response: " + samlResponse.toString(0));
		return samlResponse.getStatus();
	}

	private SAML2AuthnResponse getAuthenticationResponse(HttpServletRequest servletRequest)
			throws NIDPException
	{
		String response = servletRequest.getParameter(SAMLConstants.PARM_RESPONSE);
		Document samlResponse = getDocumentFromSAMLResponse(response);
		logger.log(Level.FINEST, "Created response document: " + samlResponse);
		Element el = samlResponse.getDocumentElement();
		try
		{
			return new SAML2AuthnResponse(el, getMeProvider(true), getBinding(servletRequest),
					m_Properties);
		}
		catch (XMLException e)
		{
			throw new NIDPException(e);
		}
	}

	private Document getDocumentFromSAMLResponse(String response) throws NIDPException
	{
		logger.log(Level.FINEST, "Encoded response: " + response);
		try
		{
			String decodedResponse = new String(Base64.decode(response));
			logger.log(Level.FINER, "Decoded response: " + decodedResponse);
			DOMParser parser = new DOMParser();
			parser.parse(new InputSource(new StringReader(decodedResponse)));
			return parser.getDocument();
		}
		catch (IOException | SAXException e)
		{
			throw new NIDPException(e);
		}
	}

	private MeProvider getMeProvider(boolean serviceProvider)
	{
		AuthnRequest areq = getAuthnRequest();
		MeDescriptor me = areq.getMeDescriptor();
		if (serviceProvider)
			return me.getMeSP();
		else
			return me.getMeIDP();
	}

	private String getBinding(HttpServletRequest servletRequest)
	{
		String cmd = servletRequest.getMethod();
		String art = servletRequest.getParameter(SAMLConstants.PARM_ARTIFACT);
		if (art != null)
			return SAMLConstants.BINDING_ARTIFACT;
		if ("post".equalsIgnoreCase(cmd))
			return SAMLConstants.BINDING_POST;
		return SAMLConstants.BINDING_REDIRECT;
	}

	private int technicalFailureOccurred()
	{
		if (errorPage == null)
			return NOT_AUTHENTICATED;
		else
			return showErrorPage();
	}

	private int startAuthenticationProcess()
	{
		if (hasSAMLRequest())
		{
			saveSAMLRequestInSession();
		}
		if (intermediatePage == null || isRestartAfterCancel())
			return redirectToExternalIdp();
		else
			return showIntermediatePage();
	}

	private void tagSessionAsCancelled()
	{
		m_Request.getSession().setAttribute(CANCEL_TAG, CANCEL_MESSAGE);
	}

	private boolean isRestartAfterCancel()
	{
		Object cancelled = m_Request.getSession().getAttribute(CANCEL_TAG);
		m_Request.getSession().removeAttribute(CANCEL_TAG);
		return CANCEL_MESSAGE.equals(cancelled);
	}

	private int redirectToExternalIdp()
	{
		String sid = retrieveSidAttribute();
		String authurl = buildAuthenticationURL(sid);
		try
		{
			m_Response.sendRedirect(authurl);
		}
		catch (IOException e)
		{
			logger.log(Level.SEVERE, "Redirect to external IDP failed: " + e.getMessage(), e);
			return technicalFailureOccurred();
		}
		return HANDLED_REQUEST;
	}

	private String retrieveSidAttribute()
	{
		return (String) m_Request.getAttribute("sid");
	}

	private void saveSAMLRequestInSession()
	{
		String sreq = inflateSAMLRequestIfNeeded( m_Request.getParameter(SAMLConstants.PARM_REQUEST) );
		logger.log(Level.FINE, "Saving SAMLRequest in sessiondata: " + sreq);
		m_SessionData.setObject(sreq);
	}

	private byte[] decompress(byte[] reqdata) throws IOException, DataFormatException 
	{
		ByteArrayInputStream bais = new ByteArrayInputStream(reqdata);
		InflaterInputStream inflater = new InflaterInputStream(bais, new Inflater(true));
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int numRead;
		byte[] data = new byte[1024];
		while ((numRead = inflater.read(data, 0, data.length)) != -1)
		{
			buffer.write(data, 0, numRead);
		}
		buffer.flush();
		return buffer.toByteArray();
	}

	private String inflateSAMLRequestIfNeeded(String request)
	{
		byte[] data = Base64.decode(request);
		try
		{
			byte[] decoded = decompress(data);
			return Base64.encodeToString(decoded, false);
		} catch(Exception e) {
			logger.log(Level.FINE, "Could not inflate SAMLRequest: " + e.getMessage());		
		}
		return request;
	}

	private String retrieveSAMLRequestFromSession()
	{
		return (String) m_SessionData.getObject();
	}

	private String buildAuthenticationURL(String sid)
	{
		StringBuilder sb = new StringBuilder();
		sb.append(URL_SEPARATOR).append(NIDP_URL_ROOT).append(URL_SEPARATOR).append(protocolHandler)
				.append(URL_SEPARATOR).append(NIDP_URL_SEND).append("?").append(NIDP_URL_ID)
				.append("=").append(idpID);
		if (sid != null)
			sb.append("&").append(NIDP_URL_SID).append("=").append(sid);
		return sb.toString();
	}

	private int showIntermediatePage()
	{
		prepareNewPage(intermediatePage);
		m_PageToShow.addAttribute(IDP_ID_TAG, idpID);
		m_PageToShow.addAttribute(SID_TAG, retrieveSidAttribute());
		return SHOW_JSP;
	}

	private int showCancelPage()
	{
		prepareNewPage(cancelPage);
		m_PageToShow.addAttribute(IDP_ID_TAG, idpID);
		m_PageToShow.addAttribute(SID_TAG, retrieveSidAttribute());
		m_PageToShow.addAttribute(SAMLConstants.PARM_REQUEST, retrieveSAMLRequestFromSession());
		m_PageToShow.addAttribute(NIDPConstants.ATTR_ERR, "U heeft het inloggen geannuleerd.");
		m_PageToShow.showPage(m_Request, m_Response);
		return 3;
	}

	private int showErrorPage()
	{
		prepareNewPage(errorPage);
		m_PageToShow.addAttribute(NIDPConstants.ATTR_ERR,
				"Er is iets fout gegaan tijdens het inloggen.");
		return SHOW_PAGE_TERMINATE;
	}

	private void prepareNewPage(String pagename)
	{
		m_PageToShow = new PageToShow(pagename);
		m_PageToShow.addAttribute(NIDPConstants.ATTR_URL,
				getReturnURL() != null ? getReturnURL() : m_Request.getRequestURL().toString());
	}
}

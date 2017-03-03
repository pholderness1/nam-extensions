package nl.idfocus.nam.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Servlet Filter implementation class ContentSecurityPolicyFilter
 */
public class ContentSecurityPolicyFilter implements Filter 
{
    private static final Logger logger = LoggerFactory.getLogger(ContentSecurityPolicyFilter.class);
	public static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";
    public static final String CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";

    /** Instruct the browser to only send reports (does not block anything) */
    private static final String REPORT_ONLY = "report-only";
    /** Instructs the browser to POST a reports of policy failures to this URI */
    public static final String REPORT_URI = "report-uri";
    /**
     * Enables a sandbox for the requested resource similar to the iframe sandbox attribute.
     * The sandbox applies a same origin policy, prevents popups, plugins and script execution is blocked.
     * You can keep the sandbox value empty to keep all restrictions in place, or add values:
     * allow-forms allow-same-origin allow-scripts, and allow-top-navigation
     */
    public static final String SANDBOX = "sandbox";
    /** The default policy for loading content such as JavaScript, Images, CSS, Font's, AJAX requests, Frames, HTML5 Media */
    public static final String DEFAULT_SRC = "default-src";
    /** Defines valid sources of images */
    public static final String IMG_SRC = "img-src";
    /** Defines valid sources of JavaScript  */
    public static final String SCRIPT_SRC = "script-src";
    /** Defines valid sources of stylesheets */
    public static final String STYLE_SRC = "style-src";
    /** Defines valid sources of fonts */
    public static final String FONT_SRC = "font-src";
    /** Applies to XMLHttpRequest (AJAX), WebSocket or EventSource */
    public static final String CONNECT_SRC = "connect-src";
    /** Defines valid sources of plugins, eg <object>, <embed> or <applet>.  */
    public static final String OBJECT_SRC = "object-src";
    /** Defines valid sources of audio and video, eg HTML5 <audio>, <video> elements */
    public static final String MEDIA_SRC = "media-src";
    /** Defines valid sources for loading frames */
    public static final String CHILD_SRC = "child-src";
    /** Defines valid sources that can be used as a HTML <form> action */
    public static final String FORM_ACTION = "form-action";
    /** Defines valid sources for embedding the resource using <frame> <iframe> <object> <embed> <applet> */
    public static final String FRAME_ANCESTORS = "frame-ancestors";
    /** Defines valid MIME types for plugins invoked via <object> and <embed> */
    public static final String PLUGIN_TYPES = "plugin-types";
    
    public static final String KEYWORD_NONE = "'none'";
    public static final String KEYWORD_SELF = "'self'";

    private boolean reportOnly;
    private String reportUri;
    private String sandbox;
    private String defaultSrc;
    private String imgSrc;
    private String scriptSrc;
    private String styleSrc;
    private String fontSrc;
    private String connectSrc;
    private String objectSrc;
    private String mediaSrc;
    private String childSrc;
    private String formAction;
    private String frameAncestors;
    private String pluginTypes;

	/**
	 * Default constructor.
	 */
	public ContentSecurityPolicyFilter()
	{
		logger.info( "Instantiating Content Security Policy Filter");
	}
    
	/**
	 * @see Filter#init(FilterConfig)
	 */
    public void init(FilterConfig filterConfig)
    {
    	try {
    		logger.info( "Initializing Content Security Policy Filter " + getClass().getPackage().getImplementationVersion());
    		
	    	// determine CSP values (filterConfig or default)
	        reportOnly = getParameterBooleanValue(filterConfig, REPORT_ONLY);
	        reportUri = getParameterValue(filterConfig, REPORT_URI);
	        sandbox = getParameterValue(filterConfig, SANDBOX);
	        defaultSrc = getParameterValue(filterConfig, DEFAULT_SRC, KEYWORD_NONE);
	        imgSrc = getParameterValue(filterConfig, IMG_SRC);
	        scriptSrc = getParameterValue(filterConfig, SCRIPT_SRC);
	        styleSrc = getParameterValue(filterConfig, STYLE_SRC);
	        fontSrc = getParameterValue(filterConfig, FONT_SRC);
	        connectSrc = getParameterValue(filterConfig, CONNECT_SRC);
	        objectSrc = getParameterValue(filterConfig, OBJECT_SRC);
	        mediaSrc = getParameterValue(filterConfig, MEDIA_SRC);
	        childSrc = getParameterValue(filterConfig, CHILD_SRC);
	        formAction = getParameterValue(filterConfig, FORM_ACTION);
	        frameAncestors = getParameterValue(filterConfig, FRAME_ANCESTORS);
	        pluginTypes = getParameterValue(filterConfig, PLUGIN_TYPES);
    	} catch (Exception e) {
    		logger.error("Unable to read Filter Configuration");
    	}
    	
    }

    private String getParameterValue(FilterConfig filterConfig, String paramName, String defaultValue) 
    {
        String value = filterConfig.getInitParameter(paramName);
        if (StringUtils.isBlank(value)) {
            value = defaultValue;
        }
        logger.info("Read string parameter {} = {}", paramName, value);
        return value;
    }

    private String getParameterValue(FilterConfig filterConfig, String paramName) 
    {
    	String value = filterConfig.getInitParameter(paramName);
    	logger.info("Read string parameter {} = {}", paramName, value);
    	return value;
    }

    private boolean getParameterBooleanValue(FilterConfig filterConfig, String paramName) 
    {
    	String value = filterConfig.getInitParameter(paramName);
    	logger.info("Read boolean parameter {} = {}", paramName, value);
        return "true".equalsIgnoreCase(value);
    }

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException 
    {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String contentSecurityPolicyHeaderName = reportOnly ? CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER : CONTENT_SECURITY_POLICY_HEADER;
        String contentSecurityPolicy = getContentSecurityPolicy();

        logger.debug("Adding Header {} = {}", contentSecurityPolicyHeaderName, contentSecurityPolicy);
        httpResponse.addHeader(contentSecurityPolicyHeaderName, contentSecurityPolicy);

        // pass the request along the filter chain
        chain.doFilter(request, response);
    }

    private String getContentSecurityPolicy() 
    {
    	// construct CSP Header value
    	StringBuilder contentSecurityPolicy = new StringBuilder(DEFAULT_SRC).append(" ").append(defaultSrc);

        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, IMG_SRC, imgSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, SCRIPT_SRC, scriptSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, STYLE_SRC, styleSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, FONT_SRC, fontSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, CONNECT_SRC, connectSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, OBJECT_SRC, objectSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, MEDIA_SRC, mediaSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, CHILD_SRC, childSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, FORM_ACTION, formAction);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, FRAME_ANCESTORS, frameAncestors);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, PLUGIN_TYPES, pluginTypes);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, REPORT_URI, reportUri);
        addSandboxDirectiveToContentSecurityPolicy(contentSecurityPolicy, sandbox);

        return contentSecurityPolicy.toString();
    }

    private void addDirectiveToContentSecurityPolicy(StringBuilder contentSecurityPolicy, String directiveName, String value) 
    {
        if (StringUtils.isNotBlank(value) && !defaultSrc.equals(value)) 
        {
            contentSecurityPolicy.append("; ").append(directiveName).append(" ").append(value);
        }
    }

    private void addSandboxDirectiveToContentSecurityPolicy(StringBuilder contentSecurityPolicy, String value) {
        if (StringUtils.isNotBlank(value)) 
        {
            if ("true".equalsIgnoreCase(value)) 
            {
                contentSecurityPolicy.append("; ").append(SANDBOX);
            } 
            else 
            {
                contentSecurityPolicy.append("; ").append(SANDBOX).append(" ").append(value);
            }
        }
    }

	/**
	 * @see Filter#destroy()
	 */
    public void destroy() 
    {
    	// Auto-generated method stub: not implemented
    }
}
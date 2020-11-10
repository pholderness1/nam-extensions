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
    public static final String REPORT_ONLY = "report-only";
    /** Instructs the browser to POST a reports of policy failures to this URI (legacy) */
    public static final String REPORT_URI = "report-uri";
    /** Instructs the browser to POST a reports of policy failures to this URI */
    public static final String REPORT_TO = "report-to";
    
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
    public static final String SCRIPT_SRC_ELEM = "script-src-elem";
    public static final String SCRIPT_SRC_ATTR = "script-src-attr";
    /** Defines valid sources of stylesheets */
    public static final String STYLE_SRC = "style-src";
    public static final String STYLE_SRC_ELEM = "style-src-elem";
    public static final String STYLE_SRC_ATTR = "style-src-attr";
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
    /** Defines valid sources for loading frames (legacy) */
    public static final String FRAME_SRC = "frame-src";
    /** Defines the URLs which may be loaded as a Worker, SharedWorker, or ServiceWorker */
    public static final String WORKER_SRC = "worker-src";
    /** Defines the URLs from which application manifests may be loaded.  */
    public static final String MANIFEST_SRC = "manifest-src";
    /** Defines the URLs from which resources may be prefetched or prerendered. */
    public static final String PREFETCH_SRC = "prefetch-src";
    /** Defines the URLs which can be used in a Document's base element. */

    public static final String BASE_URI = "base-uri";
    /** Defines valid MIME types for plugins invoked via <object> and <embed> */
    public static final String PLUGIN_TYPES = "plugin-types";
   
    /** Defines valid sources that can be used as a HTML <form> action */
    public static final String FORM_ACTION = "form-action";
    /** Defines valid sources for embedding the resource using <frame> <iframe> <object> <embed> <applet> */
    public static final String FRAME_ANCESTORS = "frame-ancestors";
    /** Defines URLs to which a document can initiate navigations by any means */
    public static final String NAVIGATE_TO = "navigate-to";
 
    public static final String KEYWORD_NONE = "'none'";
    public static final String KEYWORD_SELF = "'self'";

    enum Directive {
    	  Fetch,
    	  Document,
    	  Navigation,
    	  Reporting
    	}
    
    private boolean reportOnly;
    private String reportUri;
    private String reportTo;
    private String sandbox;
    private String defaultSrc;
    private String imgSrc;
    private String scriptSrc;
    private String scriptSrcElem;
    private String scriptSrcAttr;
    private String styleSrc;
    private String styleSrcElem;
    private String styleSrcAttr;
    private String fontSrc;
    private String connectSrc;
    private String objectSrc;
    private String mediaSrc;
    private String childSrc;
    private String workerSrc;
    private String frameSrc;
    private String manifestSrc;
    private String prefetchSrc;
    private String formAction;
    private String frameAncestors;
    private String navigateTo;
    private String baseUri;
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
	        reportTo = getParameterValue(filterConfig, REPORT_TO);
	        sandbox = getParameterValue(filterConfig, SANDBOX);
	        defaultSrc = getParameterValue(filterConfig, DEFAULT_SRC, KEYWORD_NONE);
	        imgSrc = getParameterValue(filterConfig, IMG_SRC);
	        scriptSrc = getParameterValue(filterConfig, SCRIPT_SRC);
	        scriptSrcElem = getParameterValue(filterConfig, SCRIPT_SRC_ELEM);
	        scriptSrcAttr = getParameterValue(filterConfig, SCRIPT_SRC_ATTR);
	        styleSrc = getParameterValue(filterConfig, STYLE_SRC);
	        styleSrcElem = getParameterValue(filterConfig, STYLE_SRC_ELEM);	        
	        styleSrcAttr = getParameterValue(filterConfig, STYLE_SRC_ATTR);
	        fontSrc = getParameterValue(filterConfig, FONT_SRC);
	        connectSrc = getParameterValue(filterConfig, CONNECT_SRC);
	        objectSrc = getParameterValue(filterConfig, OBJECT_SRC);
	        mediaSrc = getParameterValue(filterConfig, MEDIA_SRC);
	        childSrc = getParameterValue(filterConfig, CHILD_SRC);
	        frameSrc = getParameterValue(filterConfig, FRAME_SRC);
	        workerSrc = getParameterValue(filterConfig, WORKER_SRC);
	        manifestSrc = getParameterValue(filterConfig, MANIFEST_SRC);
	        prefetchSrc = getParameterValue(filterConfig, PREFETCH_SRC);
	        formAction = getParameterValue(filterConfig, FORM_ACTION);
	        frameAncestors = getParameterValue(filterConfig, FRAME_ANCESTORS);
	        navigateTo = getParameterValue(filterConfig, NAVIGATE_TO);
	        baseUri = getParameterValue(filterConfig, BASE_URI);
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

        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, IMG_SRC, imgSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, SCRIPT_SRC, scriptSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, SCRIPT_SRC_ELEM, scriptSrcElem, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, SCRIPT_SRC_ATTR, scriptSrcAttr, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, STYLE_SRC, styleSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, STYLE_SRC_ELEM, styleSrcElem, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, STYLE_SRC_ATTR, styleSrcAttr, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, FONT_SRC, fontSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, CONNECT_SRC, connectSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, OBJECT_SRC, objectSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, MEDIA_SRC, mediaSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, CHILD_SRC, childSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, FRAME_SRC, frameSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, WORKER_SRC, workerSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, MANIFEST_SRC, manifestSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, PREFETCH_SRC, prefetchSrc, Directive.Fetch);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, FORM_ACTION, formAction,Directive.Navigation);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, FRAME_ANCESTORS, frameAncestors,Directive.Navigation);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, NAVIGATE_TO, navigateTo,Directive.Navigation);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, BASE_URI, baseUri, Directive.Document);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, PLUGIN_TYPES, pluginTypes, Directive.Document);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, REPORT_URI, reportUri, Directive.Reporting);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, REPORT_TO, reportTo, Directive.Reporting);
        addSandboxDirectiveToContentSecurityPolicy(contentSecurityPolicy, sandbox);

        return contentSecurityPolicy.toString();
    }

    private void addDirectiveToContentSecurityPolicy(StringBuilder contentSecurityPolicy, String directiveName, String value, Directive directiveType) 
    {
        if (StringUtils.isNotBlank(value)) 
        {
        	if (directiveType == Directive.Fetch && defaultSrc.equals(value)) {
        		logger.debug("Skipping Fetch Directive {} = {}, because it is redudandant to {} = {}", directiveName, value, DEFAULT_SRC, defaultSrc);
        	} else {
        		contentSecurityPolicy.append("; ").append(directiveName).append(" ").append(value);
        	}
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
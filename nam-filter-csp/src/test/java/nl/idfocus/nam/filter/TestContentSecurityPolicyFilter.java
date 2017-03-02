package nl.idfocus.nam.filter;

import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.CHILD_SRC;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.CONNECT_SRC;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.CONTENT_SECURITY_POLICY_HEADER;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.DEFAULT_SRC;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.FONT_SRC;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.FORM_ACTION;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.FRAME_ANCESTORS;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.IMG_SRC;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.KEYWORD_SELF;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.MEDIA_SRC;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.OBJECT_SRC;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.PLUGIN_TYPES;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.REPORT_URI;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.SANDBOX;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.SCRIPT_SRC;
import static nl.idfocus.nam.filter.ContentSecurityPolicyFilter.STYLE_SRC;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import nl.idfocus.nam.filter.ContentSecurityPolicyFilter;

@RunWith(JUnit4.class)
public class TestContentSecurityPolicyFilter 
{
    private static final String DEFAULT_HEADER_VALUE = "default-src 'none'";
    private static final String REPORT_URL = "/testReportUrl";

    private ContentSecurityPolicyFilter contentSecurityPolicyFilter;
    private ServletRequest request;
    private HttpServletResponse response;
    private FilterChain filterChain;

    @Before
    public void setUp() 
    {

    	
        contentSecurityPolicyFilter = new ContentSecurityPolicyFilter();
        response = mock(HttpServletResponse.class);
        request = mock(ServletRequest.class);
        filterChain = mock(FilterChain.class);
    }

    @Test
    public void testDefaultValues() throws IOException, ServletException 
    {

        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE);
    }

    @Test
    public void testDefaultSrcIsSelf() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(KEYWORD_SELF, null, null, null, null, null, null, null, null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, "default-src 'self'");
    }

    @Test
    public void testImageSrc() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(KEYWORD_SELF, "static.example.com", null, null, null, null, null, null, null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, "default-src 'self'; img-src static.example.com");
    }

    @Test
    public void testScriptSrc() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, KEYWORD_SELF + " js.example.com", null, null, null, null, null, null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, "default-src 'none'; script-src 'self' js.example.com");
    }

    @Test
    public void testMediaSrc() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(KEYWORD_SELF, null, null, "static.example.com", null, null, null, null, null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, "default-src 'self'; media-src static.example.com");
    }
    
    @Test
    public void testStyleSrc() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null, KEYWORD_SELF + " css.example.com", null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; style-src 'self' css.example.com");
    }

    @Test
    public void testFontSrc() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null, null, KEYWORD_SELF + " font.example.com", null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; font-src 'self' font.example.com");
    }

    @Test
    public void testConnectSrc() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null, null, null, KEYWORD_SELF + " connect.example.com", null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; connect-src 'self' connect.example.com");
    }
   
    @Test
    public void testObjectSrc() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null, null, null, null, KEYWORD_SELF + " object.example.com", null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; object-src 'self' object.example.com");
    }
    
    @Test
    public void testChildSrc() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null, null, null, null, null, KEYWORD_SELF + " child.example.com", null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; child-src 'self' child.example.com");
    }
    
    @Test
    public void testformAction() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null, null, null, null, null, null, KEYWORD_SELF + " form.example.com", null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; form-action 'self' form.example.com");
    }

    @Test
    public void testframeAncestors() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null, null, null, null, null, null, null, KEYWORD_SELF + " frame.example.com", null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; frame-ancestors 'self' frame.example.com");
    }

    @Test
    public void testPluginTypes() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null, null, null, null, null, null, null, null, "application/pdf"));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; plugin-types application/pdf");
    }
    
    @Test
    public void testReportOnly() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, "true", REPORT_URL, null, null, null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER, DEFAULT_HEADER_VALUE + "; report-uri " + REPORT_URL);
    }

    @Test
    public void testReportUri() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, "false", REPORT_URL, null, null, null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; report-uri " + REPORT_URL);
    }

    @Test
    public void testSandbox() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, "true", null, null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; " + SANDBOX);
    }

    @Test
    public void testSandboxAllowScripts() throws IOException, ServletException 
    {
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, "allow-scripts", null, null, null, null, null, null, null, null));
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; " + SANDBOX + " allow-scripts");
    } 
    
	/**
	 * -------------------------- HELPER methods -------------------------------
	 */
    
    private FilterConfig mockFilterConfig(String defaultSrc, String imgSrc, String scriptSrc, String mediaSrc, String reportOnly, String reportUri,
            String sandbox, String styleSrc, String fontSrc, String connectSrc, String objectSrc, String childSrc, String formAction, 
            String frameAncestors, String pluginTypes) 
    {
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter(DEFAULT_SRC)).thenReturn(defaultSrc);
        when(filterConfig.getInitParameter(IMG_SRC)).thenReturn(imgSrc);
        when(filterConfig.getInitParameter(SCRIPT_SRC)).thenReturn(scriptSrc);
        when(filterConfig.getInitParameter(MEDIA_SRC)).thenReturn(mediaSrc);
        when(filterConfig.getInitParameter("report-only")).thenReturn(reportOnly);
        when(filterConfig.getInitParameter(REPORT_URI)).thenReturn(reportUri);
        when(filterConfig.getInitParameter(SANDBOX)).thenReturn(sandbox);
        when(filterConfig.getInitParameter(STYLE_SRC)).thenReturn(styleSrc);
        when(filterConfig.getInitParameter(FONT_SRC)).thenReturn(fontSrc);
        when(filterConfig.getInitParameter(CONNECT_SRC)).thenReturn(connectSrc);
        when(filterConfig.getInitParameter(OBJECT_SRC)).thenReturn(objectSrc);
        when(filterConfig.getInitParameter(CHILD_SRC)).thenReturn(childSrc);
        when(filterConfig.getInitParameter(FORM_ACTION)).thenReturn(formAction);
        when(filterConfig.getInitParameter(FRAME_ANCESTORS)).thenReturn(frameAncestors);
        when(filterConfig.getInitParameter(PLUGIN_TYPES)).thenReturn(pluginTypes);
        
        return filterConfig;
    }

    private Header getHeader() 
    {
        ArgumentCaptor<String> headerName = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> headerValue = ArgumentCaptor.forClass(String.class);
        verify(response).addHeader(headerName.capture(), headerValue.capture());
        return new Header(headerName.getValue(), headerValue.getValue());
    }

    private void assertHeader(String expectedHeaderName, String expectedHeaderValue) 
    {
        Header header = getHeader();
        assertEquals(expectedHeaderName, header.name);
        assertEquals(expectedHeaderValue, header.value);
    }

    private static final class Header 
    {
        public String name;
        public String value;

        public Header(String name, String value) 
        {
            this.name = name;
            this.value = value;
        }
    }
}
package nl.idfocus.nam.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.HttpCookie;
import java.util.Collection;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SameSiteFilter implements javax.servlet.Filter {

    /** Class logger. */
    private static final Logger logger = LoggerFactory.getLogger(SameSiteFilter.class);

    /** The name of set cookie header field name. */
    private static final String SET_COOKIE="Set-Cookie";

    /** The name of the same-site cookie attribute. */
    private static final String SAMESITE_ATTRIBITE_NAME="SameSite";


    /** {@inheritDoc} */
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        logger.info( "Initializing SameSite Cookie Header Filter " + getClass().getPackage().getImplementationVersion());
    }

    /** {@inheritDoc} */
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("Request is not an instance of HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("Response is not an instance of HttpServletResponse");
        }

        chain.doFilter(request, (ServletResponse) new SameSiteResponseProxy((HttpServletResponse)response));
    }

    /**
     * An implementation of the {@link HttpServletResponse} which adds the same-site flag to {@literal Set-Cookie}
     * headers for the set of configured cookies.
     */
    private class SameSiteResponseProxy extends HttpServletResponseWrapper{

        /** The response. */
        private final HttpServletResponse response;

        /**
         * Constructor.
         *
         * @param resp the response to delegate to
         */
        public SameSiteResponseProxy(final HttpServletResponse resp) {
            super(resp);
            response = resp;
        }

        /** {@inheritDoc} */
        @Override
        public void sendError(final int sc) throws IOException {
            appendSameSite();
            super.sendError(sc);
        }

        /** {@inheritDoc} */
        @Override
        public PrintWriter getWriter() throws IOException {
            appendSameSite();
            return super.getWriter();
        }

        /** {@inheritDoc} */
        @Override
        public void sendError(final int sc, final String msg) throws IOException {
            appendSameSite();
            super.sendError(sc, msg);
        }

        /** {@inheritDoc} */
        @Override
        public void sendRedirect(final String location) throws IOException {
            appendSameSite();
            super.sendRedirect(location);
        }

        /** {@inheritDoc} */
        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            appendSameSite();
            return super.getOutputStream();
        }

        /**
         * Append the SameSite cookie attribute with the sameSite-value "None" to the {@code cookieHeader}
         * if it does not already have one set.
         */
        private void appendSameSite() {

            final Collection<String> cookieheaders = response.getHeaders(SET_COOKIE);

            boolean firstHeader = true;
            for (final String cookieHeader : cookieheaders) {
                logger.trace("Parsing Cookie header [{}] ",cookieHeader);

                if (StringUtils.trimToNull(cookieHeader)==null) {
                    logger.info("Skipping Cookie header [{}] because of emtpy value ",cookieHeader);
                    continue;
                }

                List<HttpCookie> parsedCookies = null;
                try {
                    //this parser only parses name and value, we only need the name.
                    parsedCookies = HttpCookie.parse(cookieHeader);
                } catch(final IllegalArgumentException e) {
                    //should not get here
                   logger.info("Cookie header [{}] violates the cookie specification and will be ignored",cookieHeader);
                }

                if (parsedCookies==null || parsedCookies.size()!=1) {
                    logger.info("Skipping Cookie header [{}] because of Cookie size not equal 1",cookieHeader);
                	//should be one cookie
                    continue;
                }

                //only add if does not already exist, else keep current value
                String sameSiteSetCookieValue =  cookieHeader;
                  if (!cookieHeader.contains(SAMESITE_ATTRIBITE_NAME)) {
                	  sameSiteSetCookieValue = String.format("%s; %s", cookieHeader, SAMESITE_ATTRIBITE_NAME+"=None");
                }

                if (firstHeader) {
                	 logger.trace("Setting First Cookie header to [{}]", sameSiteSetCookieValue);
                	response.setHeader(SET_COOKIE, sameSiteSetCookieValue);
                    firstHeader = false;
                    continue;
                }
           	 	logger.trace("Setting Secondary Cookie header to [{}]", sameSiteSetCookieValue);
                response.addHeader(SET_COOKIE, sameSiteSetCookieValue);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void destroy() {
    }
}

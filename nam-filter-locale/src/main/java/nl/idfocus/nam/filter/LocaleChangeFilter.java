package nl.idfocus.nam.filter;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.LocaleUtils;
import org.apache.commons.lang.StringUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.idfocus.nam.util.CookieUtils;

/**
 * A servlet filter that overrides the request locale.
 *
 * @author Sebastiaan Veldhuisen
 */
public class LocaleChangeFilter implements Filter {

	/**
	 * Default language cookie name.
	 */
	public static final String DEFAULT_COOKIE_NAME = "locale";

	/**
	 * Default locale querystring parameter, if none is specified in filter's
	 * InitParams
	 */
	public static final String DEFAULT_LOCALE_QUERY_STRING = "locale";

	public static final String COOKIE_NAME_INITPARAM_KEY = "cookieName";
	public static final String COOKIE_DOMAIN_INITPARAM_KEY = "cookieDomain";
	public static final String COOKIE_PATH_INITPARAM_KEY = "cookiePath";
	public static final String COOKIE_MAX_AGE_INITPARAM_KEY = "cookieMaxAge";
	public static final String COOKIE_SECURE_INITPARAM_KEY = "cookieSecure";
	public static final String LOCALE_QUERY_STRING_INITPARAM_KEY = "localeQuerystringParam";

	private static final Logger logger = LoggerFactory.getLogger(LocaleChangeFilter.class);

	private String localeQuerystringParam;

	private String cookieName;

	private String cookieDomain;

	private String cookiePath;

	private Integer cookieMaxAge;

	private boolean cookieSecure;

	/**
	 * Default constructor.
	 */
	public LocaleChangeFilter() {
		logger.info("Instantiating Locale Change Filter");
	}

	/**
	 * @see Filter#init(FilterConfig)
	 */
	public void init(FilterConfig filterConfig) {
		try {
			logger.info("Initializing Locale Change Filter " + getClass().getPackage().getImplementationVersion());

			// determine Filter values (filterConfig or default)
			this.localeQuerystringParam = getParameterValue(filterConfig, LOCALE_QUERY_STRING_INITPARAM_KEY,
					DEFAULT_LOCALE_QUERY_STRING);
			this.cookieName = getParameterValue(filterConfig, COOKIE_NAME_INITPARAM_KEY, DEFAULT_COOKIE_NAME);
			this.cookieDomain = getParameterValue(filterConfig, COOKIE_DOMAIN_INITPARAM_KEY);
			this.cookiePath = getParameterValue(filterConfig, COOKIE_PATH_INITPARAM_KEY);
			this.cookieMaxAge = getParameterIntegerValue(filterConfig, COOKIE_MAX_AGE_INITPARAM_KEY);
			this.cookieSecure = getParameterBooleanValue(filterConfig, COOKIE_SECURE_INITPARAM_KEY);
		} catch (Exception e) {
			logger.error("Unable to read Filter Configuration");
		}
	}

	private String getParameterValue(FilterConfig filterConfig, String paramName) {
		String value = filterConfig.getInitParameter(paramName);
		logger.info("Read string parameter {} = {}", paramName, value);

		return value;
	}

	private String getParameterValue(FilterConfig filterConfig, String paramName, String defaultValue) {
		String value = filterConfig.getInitParameter(paramName);
		if (StringUtils.isBlank(value)) {
			value = defaultValue;
		}
		logger.info("Read string parameter {} = {}", paramName, value);

		return value;
	}

	private boolean getParameterBooleanValue(FilterConfig filterConfig, String paramName) {
		String value = filterConfig.getInitParameter(paramName);
		logger.info("Read boolean parameter {} = {}", paramName, value);
		return "true".equalsIgnoreCase(value);
	}

	private Integer getParameterIntegerValue(FilterConfig filterConfig, String paramName) {
		String value = filterConfig.getInitParameter(paramName);
		Integer valueInt;
		try {
			valueInt = Integer.parseInt(value);
		} catch (NumberFormatException e) {
			valueInt = null;
		}
		logger.info("Read integer parameter {} = {}", paramName, valueInt);

		return valueInt;
	}

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
			throws IOException, ServletException {
		final HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
		final HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

		// determine preferred locale
		final Locale acceptHeaderLocale = findAcceptHeaderLocale(httpServletRequest);
		final Locale cookieLocale = findCookieLocale(httpServletRequest);
		final Locale querystringLocale = findQuerystringLocale(httpServletRequest);
		final Locale systemLocale = findSystemLocale();
		final Locale locale = determineOverridingLocale(acceptHeaderLocale, cookieLocale, querystringLocale,
				systemLocale);

		// bake a cookie :-)
		bakeLocaleCookie(httpServletRequest, httpServletResponse, locale);

		// pass the request along the filter chain
		filterChain.doFilter(new LocaleOverrideRequest(httpServletRequest, locale), servletResponse);
	}

	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {
		/* intentionally left blank */
	}

	protected void bakeLocaleCookie(HttpServletRequest request, HttpServletResponse response, Locale locale) {
		Cookie cookie = CookieUtils.getCookie(request, cookieName);

		if (cookie == null) {
			cookie = CookieUtils.createCookie(cookieName, locale.toString(), cookieDomain, cookiePath);
		} else {
			cookie.setValue(locale.toString());
		}

		CookieUtils.addCookie(response, cookie, cookieMaxAge, cookieSecure);
	}

	protected Locale determineOverridingLocale(Locale acceptHeaderLocale, Locale cookieLocale, Locale querystringLocale,
			Locale systemLocale) {
		if (querystringLocale != null) {
			return querystringLocale;
		}

		if (cookieLocale != null) {
			return cookieLocale;
		}

		if (acceptHeaderLocale != null) {
			return acceptHeaderLocale;
		}

		return systemLocale;
	}

	protected Locale findAcceptHeaderLocale(HttpServletRequest request) {
		return request.getLocale();
	}

	protected Locale findCookieLocale(HttpServletRequest httpServletRequest) {
		final Cookie cookie = CookieUtils.getCookie(httpServletRequest, cookieName);

		if (cookie != null) {
			final String value = cookie.getValue();
			return stringToLocale(value);
		}

		return null;
	}

	protected Locale findQuerystringLocale(HttpServletRequest request) {
		final String localParam = request.getParameter(localeQuerystringParam);
		return stringToLocale(localParam);
	}

	protected Locale findSystemLocale() {
		return Locale.getDefault();
	}

	private Locale stringToLocale(String string) {
		if (string != null) {
			try {
				return LocaleUtils.toLocale(string);
			} catch (final IllegalArgumentException illegalArgumentException) {
				logger.warn("Invalid locale string: {}; returning null", string);
			}
		}

		return null;
	}

}
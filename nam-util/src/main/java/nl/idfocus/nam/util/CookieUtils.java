package nl.idfocus.nam.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Sebastiaan Veldhuisen
 */
public abstract class CookieUtils {

	public static final String DEFAULT_COOKIE_PATH = "/";

	public static void addCookie(HttpServletResponse response, Cookie cookie, Integer maxAge, Boolean secure, Boolean httpOnly,
			String domain, String path) {
		if (maxAge != null) {
			cookie.setMaxAge(maxAge);
		}

		if (secure != null) {
			cookie.setSecure(secure);
		}

		if (httpOnly != null) {
			cookie.setHttpOnly(httpOnly);
		}

		if (domain != null) {
			cookie.setDomain(domain);
		}

		if (path != null) {
			cookie.setPath(path);
		}

		response.addCookie(cookie);
	}

	public static Cookie createCookie(String name, String value, String domain, String path) {
		final Cookie cookie = new Cookie(name, value);

		if (domain != null) {
			cookie.setDomain(domain);
		}

		if (path == null) {
			cookie.setPath(CookieUtils.DEFAULT_COOKIE_PATH);
		} else {
			cookie.setPath(path);
		}

		return cookie;
	}

	public static Cookie getCookie(HttpServletRequest request, String name) {
		final Cookie cookies[] = request.getCookies();

		if (cookies != null) {
			for (final Cookie cookie : cookies) {
				if (name.equals(cookie.getName())) {
					return cookie;
				}
			}
		}

		return null;
	}

}
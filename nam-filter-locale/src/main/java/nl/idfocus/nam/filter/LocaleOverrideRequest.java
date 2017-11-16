package nl.idfocus.nam.filter;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * @author Sebastiaan Veldhuisen
 */
public class LocaleOverrideRequest extends HttpServletRequestWrapper {

	private final Locale locale;

	public LocaleOverrideRequest(HttpServletRequest request, Locale locale) {
		super(request);
		this.locale = locale;
	}

	@Override
	public Locale getLocale() {
		return locale != null ? locale : super.getLocale();
	}

	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public Enumeration getLocales() {
		if (locale == null) {
			return super.getLocales();
		} else {
			List<Locale> locales = Collections.list(super.getLocales());

			if (locales.contains(locale)) {
				locales.remove(locale);
			}

			locales.add(0, locale);
			return Collections.enumeration(locales);
		}
	}

}
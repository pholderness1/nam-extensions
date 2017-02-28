package nl.idfocus.nam.sms;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

import java.io.IOException;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

import org.skyscreamer.jsonassert.JSONCompareMode;

import nl.idfocus.nam.util.LogFormatter;
import nl.rgn.sms.BerichtenCentrum;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.MappingBuilder;
import com.github.tomakehurst.wiremock.client.RequestPatternBuilder;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.UrlMatchingStrategy;
import com.github.tomakehurst.wiremock.client.ValueMatchingStrategy;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

public class BerichtenCentrumService
{
	private static final Logger		logger			= LogFormatter
			.getConsoleLogger(BerichtenCentrumService.class.getName());

	public static final String		SERVICE_URL			= "/berichtencentrum/1/direct-sms";
	public static final String		APPLICATION_ID		= "Mobile API";
	public static final String		API_KEY	= "67821-8792102-8923";
	private final WireMockServer	wireMockServer;

	private final int				port;

	private BerichtenCentrumService(int port, boolean secure)
	{
		this.port = port;
		logger.info("Starting embedded Berichtencentrum Service on port " + port);
		WireMockConfiguration config = wireMockConfig();
		if (secure)
		{
			config.httpsPort(port);
			disableSSLHostnameVerification();
		}
		else
		{
			config.port(port);
		}
		wireMockServer = new WireMockServer(config);
		wireMockServer.start();
		wireMockServer.stubFor(validSmsRequest().atPriority(1));
		wireMockServer.stubFor(invalidSmsRequest().atPriority(10));
	}

	private MappingBuilder validSmsRequest()
	{
		MappingBuilder bldr = postBuilder(urlEqualTo(SERVICE_URL));
		ValueMatchingStrategy strategy = matchJsonFieldExact(BerichtenCentrum.PARAM_API_KEY,API_KEY);
		return bldr.withRequestBody(strategy)
				.willReturn(getSuccessResponseDefinition());
	}

	private MappingBuilder invalidSmsRequest()
	{
		MappingBuilder bldr = postBuilder(urlEqualTo(SERVICE_URL));
		ValueMatchingStrategy strategy = matchStringContainment("");
		return bldr.withRequestBody(strategy)
				.willReturn(getFailureResponseDefinition().withBody(createInvalidSmsMessage()));
	}

	private MappingBuilder postBuilder(UrlMatchingStrategy strategy)
	{
		return post(strategy);
	}

	private ValueMatchingStrategy matchStringContainment(String content)
	{
		ValueMatchingStrategy strategy = new ValueMatchingStrategy();
		strategy.setContains(content);
		return strategy;
	}

	private ValueMatchingStrategy matchJsonFieldExact(String jsonField, String jsonContent)
	{
		ValueMatchingStrategy strategy = new ValueMatchingStrategy();
		strategy.setEqualToJson("{\""+jsonField+"\":\""+jsonContent+"\"}");
		strategy.setJsonCompareMode(JSONCompareMode.LENIENT);
		return strategy;
	}

	private ResponseDefinitionBuilder getSuccessResponseDefinition()
	{
		return aResponse().withStatus(202).withHeader("Content-Type", "text/json");
	}

	private ResponseDefinitionBuilder getFailureResponseDefinition()
	{
		return aResponse().withStatus(400).withHeader("Content-Type", "text/json");
	}

	private String createInvalidSmsMessage()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("{").append("\"error\":").append("}");
		return sb.toString();
	}

	private void disableSSLHostnameVerification()
	{
		HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier()
		{
			public boolean verify(String hostname, SSLSession session)
			{
				System.out.println("Did NOT verify SSL hostname: " + hostname);
				return true;
			}
		});
	}

	public void shutdown()
	{
		wireMockServer.stop();
	}

	/**
	 * Start a new webservice
	 * 
	 * @return
	 */
	public static BerichtenCentrumService startNewPlaintextService(int port) throws IOException
	{
		return new BerichtenCentrumService(port, false);
	}

	/**
	 * Start a new webservice
	 * 
	 * @return
	 */
	public static BerichtenCentrumService startNewSSLService(int port) throws IOException
	{
		return new BerichtenCentrumService(port, true);
	}

	public void verify(RequestPatternBuilder requestPatternBuilder)
	{
		wireMockServer.verify(requestPatternBuilder);
	}

	public int getPort()
	{
		return port;
	}

	public static void main(String[] args) throws IOException
	{
		startNewSSLService(8081);
	}
}

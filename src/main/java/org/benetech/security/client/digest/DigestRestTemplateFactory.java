package org.benetech.security.client.digest;

import java.nio.charset.Charset;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;

/**
 * Factory to create RestTemplate client objects that can use Digest
 * Authentication.
 * 
 * @see <a href=
 *      "http://www.baeldung.com/resttemplate-digest-authentication">http://www.baeldung.com/resttemplate-digest-authentication</a>
 * @author Eugen Paraschiv <http://www.baeldung.com/author/eugen/>
 *
 */
public class DigestRestTemplateFactory {

	public static RestTemplate getRestTemplate(String hostname, int port, String scheme, String realmName,
			String username, String password) {
		HttpHost host = new HttpHost(hostname, port, scheme);
		CloseableHttpClient client = HttpClientBuilder.create()
				.setDefaultCredentialsProvider(provider(username, password)).useSystemProperties().build();
		HttpComponentsClientHttpRequestFactoryDigestAuth requestFactory = new HttpComponentsClientHttpRequestFactoryDigestAuth();
		requestFactory.setHttpClient(client);
		requestFactory.setHost(host);
		requestFactory.setRealmName(realmName);
		requestFactory.setBufferRequestBody(false);
		RestTemplate restTemplate = new RestTemplate(requestFactory);

		// Add converters for multi-part form submission
		FormHttpMessageConverter formConverter = new FormHttpMessageConverter();
		formConverter.setCharset(Charset.forName("UTF8"));
		restTemplate.getMessageConverters().add(formConverter);
		restTemplate.getMessageConverters().add(new MappingJackson2HttpMessageConverter());

		return restTemplate;
	}

	private static CredentialsProvider provider(String username, String password) {
		CredentialsProvider provider = new BasicCredentialsProvider();
		UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(username, password);
		provider.setCredentials(AuthScope.ANY, credentials);
		return provider;
	}
}

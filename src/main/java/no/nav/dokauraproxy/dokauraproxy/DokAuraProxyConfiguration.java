package no.nav.dokauraproxy.dokauraproxy;

import no.nav.security.token.support.spring.api.EnableJwtTokenValidation;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.http.io.SocketConfig;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.apache.hc.core5.util.Timeout.ofSeconds;

@Configuration
@EnableWebMvc
@EnableJwtTokenValidation(ignore = {"org.springframework", "org.springdoc"})
@EnableConfigurationProperties({NaisProperties.class, DokAuraProxyProperties.class})
@ComponentScan
public class DokAuraProxyConfiguration {

	@Bean
	ClientHttpRequestFactory clientHttpRequestFactory(HttpClient httpClient) {
		HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
		// Default timeouts for alle restklienter som bruker denne requestFactory.
		// RestTemplate som behøver egne timeouts må konstruere en ny ClientHttpRequestFactory.
		httpComponentsClientHttpRequestFactory.setConnectTimeout(5_000);
		return httpComponentsClientHttpRequestFactory;
	}

	@Bean
	HttpClient httpClient() {
		var readTimeout = SocketConfig.custom().setSoTimeout(ofSeconds(20)).build();
		PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
		connectionManager.setMaxTotal(400);
		connectionManager.setDefaultMaxPerRoute(100);
		connectionManager.setDefaultSocketConfig(readTimeout);

		return HttpClients.custom()
				.setConnectionManager(connectionManager)
				.build();
	}
}

package no.nav.dokauraproxy.dokauraproxy;


import com.github.tomakehurst.wiremock.client.WireMock;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback;
import no.nav.security.token.support.spring.test.EnableMockOAuth2Server;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.wiremock.spring.EnableWireMock;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.common.Encoding.urlEncode;
import static com.github.tomakehurst.wiremock.core.Options.DYNAMIC_PORT;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@ActiveProfiles(value = {"itest"})
@EnableMockOAuth2Server
@EnableWireMock
class RestStsToEntraIdTokenExchangeControllerIT {

	RestClient restClient = RestClient.builder().build();

	@AfterEach
	void tearDown() {
		WireMock.reset();
	}

	@Autowired
	private MockOAuth2Server server;

	@LocalServerPort
	int localServerPort;

	@Test
	void requestTokenWithScopeSuccessfully() {
		stubTexasToken();

		String requestedScope = "api://dev-itest.testtest.fest/.default";
		var token = getTokenForScope(requestedScope);

		verify(1, postRequestedFor(urlEqualTo("/nais/token")).withRequestBody(containing(urlEncode(requestedScope))));
		assertThat(token.access_token()).isEqualTo("yeehaw");
		assertThat(token.token_type()).isEqualTo("Bearer");
	}

	@Test
	void requestingTokenWithScopeNoAccessIsDenied() {
		var xyzzy = assertThrows(RestClientResponseException.class,
				() -> getTokenForScope("api://dev-itest.testtest.no-access-api/.default"));

		assertThat(xyzzy.getStatusCode()).isEqualTo(FORBIDDEN);
		assertThat(xyzzy.getResponseBodyAsString()).contains("you are requesting a scope you do not have access to");

		verify(0, postRequestedFor(urlEqualTo("/nais/token")));
	}

	@Test
	void requestingTokenWithSTSTokenInvalidAudienceDenied() {
		var xyzzy = assertThrows(RestClientResponseException.class,
				() -> restClient.post()
						.uri("http://localhost:{port}/rest/fetchEntraIdToken", localServerPort)
						.contentType(TEXT_PLAIN)
						.accept(APPLICATION_JSON)
						.header(AUTHORIZATION, "Bearer " + jwt("srvtest", "dev-itest:invalid:audience"))
						.body("api://dev-itest.testtest.no-access-api/.default")
						.retrieve()
						.body(TokenResponse.class));

		assertThat(xyzzy.getStatusCode()).isEqualTo(UNAUTHORIZED);
		assertThat(xyzzy.getResponseBodyAsString()).contains("\"error\":\"Unauthorized\"");

		verify(0, postRequestedFor(urlEqualTo("/nais/token")));
	}

	@Test
	void requestingTokenWithMalformedScopeDenied() {
		var xyzzy = assertThrows(RestClientResponseException.class,
				() -> getTokenForScope("api://dev-itest.testtest.no-access-api/.default; -- drop table * "));

		assertThat(xyzzy.getStatusCode()).isEqualTo(FORBIDDEN);
		assertThat(xyzzy.getResponseBodyAsString()).contains("you are requesting a scope you do not have access to");

		verify(0, postRequestedFor(urlEqualTo("/nais/token")));
	}

	private TokenResponse getTokenForScope(String requestedScope) {
		return restClient.post()
				.uri("http://localhost:{port}/rest/fetchEntraIdToken", localServerPort)
				.contentType(TEXT_PLAIN)
				.accept(APPLICATION_JSON)
				.header(AUTHORIZATION, "Bearer " + jwt())
				.body(requestedScope)
				.retrieve()
				.body(TokenResponse.class);
	}

	public static void stubTexasToken() {
		stubFor(post("/nais/token").willReturn(aResponse().withStatus(OK.value())
				.withHeader(CONTENT_TYPE, APPLICATION_JSON_VALUE)
				.withBodyFile("texas/texas_happy.json")));
	}

	protected String jwt() {
		return jwt("srvtest", "dev-itest:teamdokumenthandtering:dokauraproxy");
	}

	protected String jwt(String subject, String audience) {
		String issuerId = "reststs";
		return server.issueToken(
				issuerId,
				"dokprodbatch-clientid",
				new DefaultOAuth2TokenCallback(
						issuerId,
						subject,
						"JWT",
						List.of(audience),
						emptyMap(),
						60
				)
		).serialize();
	}
}
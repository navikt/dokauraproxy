package no.nav.dokauraproxy.dokauraproxy;

import com.github.tomakehurst.wiremock.client.WireMock;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback;
import no.nav.security.token.support.spring.test.EnableMockOAuth2Server;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.client.RestTestClient;
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
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@ActiveProfiles(value = {"itest"})
@EnableMockOAuth2Server
@EnableWireMock
class RestStsToEntraIdTokenExchangeControllerIT {

	RestTestClient restClient;

	@AfterEach
	void tearDown() {
		WireMock.reset();
	}

	@Autowired
	private MockOAuth2Server server;

	@LocalServerPort
	int localServerPort;

	@BeforeEach
	void setup() {
		restClient = RestTestClient.bindToServer()
				.baseUrl("http://localhost:%d/rest/fetchEntraIdToken".formatted(localServerPort))
				.defaultHeader(CONTENT_TYPE, TEXT_PLAIN_VALUE)
				.defaultHeader(ACCEPT, APPLICATION_JSON_VALUE)
				.build();
	}

	@Test
	void requestTokenWithScopeSuccessfully() {
		stubTexasToken();

		String requestedScope = "api://dev-itest.testtest.fest/.default";
		var token = restClient.post()
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt())
				.body(requestedScope)
				.exchange()
				.expectStatus().isOk()
				.returnResult(TokenResponse.class)
				.getResponseBody();

		verify(1, postRequestedFor(urlEqualTo("/nais/token")).withRequestBody(containing(urlEncode(requestedScope))));
		assertThat(token.access_token()).isEqualTo("yeehaw");
		assertThat(token.token_type()).isEqualTo("Bearer");
	}

	@Test
	void requestingTokenWithScopeNoAccessIsDenied() {
		var response = restClient.post()
				.header(AUTHORIZATION, "Bearer " + jwt())
				.body("api://dev-itest.testtest.no-access-api/.default")
				.exchange()
				.expectStatus().isForbidden()
				.returnResult(String.class)
				.getResponseBody();

		assertThat(response).contains("you are requesting a scope you do not have access to");

		verify(0, postRequestedFor(urlEqualTo("/nais/token")));
	}

	@Test
	void requestingTokenWithSTSTokenInvalidAudienceDenied() {
		var response = restClient.post()
				.header(AUTHORIZATION, "Bearer " + jwt("srvtest", "dev-itest:invalid:audience"))
				.body("api://dev-itest.testtest.no-access-api/.default")
				.exchange()
				.expectStatus().isUnauthorized()
				.returnResult(String.class)
				.getResponseBody();

		assertThat(response).contains("\"error\":\"Unauthorized\"");

		verify(0, postRequestedFor(urlEqualTo("/nais/token")));
	}

	@Test
	void requestingTokenWithMalformedScopeDenied() {
		var response = restClient.post()
				.header(AUTHORIZATION, "Bearer " + jwt())
				.body("api://dev-itest.testtest.no-access-api/.default; -- drop table * ")
				.exchange()
				.expectStatus().isForbidden()
				.returnResult(String.class)
				.getResponseBody();

		assertThat(response).contains("you are requesting a scope you do not have access to");

		verify(0, postRequestedFor(urlEqualTo("/nais/token")));
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
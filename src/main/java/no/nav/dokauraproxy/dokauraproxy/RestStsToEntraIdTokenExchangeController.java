package no.nav.dokauraproxy.dokauraproxy;

import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import static java.util.Objects.requireNonNull;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;

@Protected
@RestController
@RequestMapping("rest/")
public class RestStsToEntraIdTokenExchangeController {

	private static final Logger log = LoggerFactory.getLogger(RestStsToEntraIdTokenExchangeController.class);

	private static final String MDC_CONSUMER_ID = "consumerId";
	private static final String MDC_USER_ID = "userId";
	private static final String MDC_USER_NAME = "userName";
	public static final String RESTSTS_ISSUER = "reststs";

	private final RestClient restClient;
	private final NaisProperties naisProperties;
	private final DokAuraProxyProperties dokAuraProxyProperties;
	private final TokenValidationContextHolder tokenValidationContextHolder;

	public RestStsToEntraIdTokenExchangeController(NaisProperties naisProperties,
												   DokAuraProxyProperties dokAuraProxyProperties,
												   RestClient.Builder restClientBuilder,
												   ClientHttpRequestFactory clientHttpRequestFactory,
												   TokenValidationContextHolder tokenValidationContextHolder
	) {
		this.naisProperties = naisProperties;
		this.dokAuraProxyProperties = dokAuraProxyProperties;
		this.tokenValidationContextHolder = tokenValidationContextHolder;
		this.restClient = restClientBuilder
				.requestFactory(clientHttpRequestFactory)
				.build();
	}

	@GetMapping("fetchEntraIdToken")
	public ResponseEntity<String> exchangeToken(@RequestHeader("Authorization") String authorizationHeader) {
		try {
			validateStsToken(authorizationHeader);

			MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
			formData.add("identity_provider", "azuread");
			formData.add("target", dokAuraProxyProperties.targetScope());
			String accessToken = requireNonNull(restClient.post()
					.uri(naisProperties.tokenEndpoint())
					.contentType(APPLICATION_FORM_URLENCODED)
					.body(formData)
					.retrieve()
					.body(TokenResponse.class))
					.access_token();
			log.info("Hentet ny EntraId-token for applikasjon autentisert med Rest STS");
			return ResponseEntity.ok(accessToken);
		} catch (InvalidRestStsTokenException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body("Provided token was not from the Rest STS issuer, or did not have the correct audience");
		} catch (Exception e) {
			log.error("Uventet feil: {}", e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
	}

	private void validateStsToken(String authorizationHeader) {
		TokenValidationContext tokenValidationContext = tokenValidationContextHolder.getTokenValidationContext();
		JwtToken token = tokenValidationContext.getJwtToken(RESTSTS_ISSUER);
		if (authorizationHeader != null && token != null) {
			populateMDCFromToken(token);
		} else {
			throw new InvalidRestStsTokenException("Unable to successfully validate RestSTS token");
		}
	}

	private void populateMDCFromToken(JwtToken token) {
		String consumerId = token.getSubject();
		MDC.put(MDC_CONSUMER_ID, consumerId);
		MDC.put(MDC_USER_ID, consumerId);
		MDC.put(MDC_USER_NAME, consumerId);
	}

	static class InvalidRestStsTokenException extends RuntimeException {
		public InvalidRestStsTokenException(String message) {
			super(message);
		}
	}
}

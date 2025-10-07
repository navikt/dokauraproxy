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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@Protected
@RestController
@RequestMapping(value = "rest/", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
public class RestStsToEntraIdTokenExchangeController {

	private static final Logger log = LoggerFactory.getLogger(RestStsToEntraIdTokenExchangeController.class);
	private static final Pattern SCOPE_PATTERN = Pattern.compile("^api://[a-z-]+\\.[a-z]+\\.[a-z0-9-]+/\\.default$");
	private static final String MDC_CONSUMER_ID = "consumerId";
	private static final String MDC_USER_ID = "userId";
	private static final String MDC_USER_NAME = "userName";
	private static final String RESTSTS_ISSUER = "reststs";

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

			String tokenResponse = getTokenFromTexas(dokAuraProxyProperties.targetScope());
			log.info("Hentet ny EntraId-token for applikasjon autentisert med Rest STS ({}) og scope {}", MDC.get(MDC_CONSUMER_ID), dokAuraProxyProperties.targetScope());
			return ResponseEntity.ok(tokenResponse);
		} catch (RestStsTokenExchangeException e) {
			log.error("Ugyldig request fra {}: {}", MDC.get(MDC_CONSUMER_ID), e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.FORBIDDEN)
					.body("Provided token was not from the Rest STS issuer, or did not have the correct audience");
		} catch (HttpClientErrorException e) {
			log.error("Kall mot EntraID feilet: {}", e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
					.body("Unable to acquire token. Please check the logs.");
		} catch (Exception e) {
			log.error("Uventet feil: {}", e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
	}

	@PostMapping(value = "fetchEntraIdToken", consumes = TEXT_PLAIN_VALUE)
	public ResponseEntity<String> exchangeTokenWithScope(@RequestHeader("Authorization") String authorizationHeader, @RequestBody String scope) {
		try {
			validateStsTokenAndRequestedScope(authorizationHeader, scope);

			String tokenResponse = getTokenFromTexas(scope);
			log.info("Hentet ny EntraId-token for applikasjon autentisert med Rest STS ({}) og scope {}", MDC.get(MDC_CONSUMER_ID), scope);
			return ResponseEntity.ok(tokenResponse);
		} catch (RestStsTokenExchangeException e) {
			log.error("Ugyldig request fra {}: {}", MDC.get(MDC_CONSUMER_ID), e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.FORBIDDEN)
					.body("Provided token was not from the Rest STS issuer, is not authorized, or you are requesting a " +
							"scope you do not have access to. Check that your app is authorized for the requested scope " +
							"in dokauraproxy config, and check the logs.");
		} catch (HttpClientErrorException e) {
			log.error("Kall mot EntraID feilet: {}", e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
					.body("Unable to acquire token. Please check the logs.");
		} catch (Exception e) {
			log.error("Uventet feil: {}", e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
	}

	private String getTokenFromTexas(String scope) {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
		formData.add("identity_provider", "azuread");
		formData.add("target", scope);
		return requireNonNull(restClient.post()
				.uri(naisProperties.tokenEndpoint())
				.contentType(APPLICATION_FORM_URLENCODED)
				.body(formData)
				.retrieve()
				.body(String.class));
	}

	private void validateStsTokenAndRequestedScope(String authorizationHeader, String scope) {
		TokenValidationContext tokenValidationContext = tokenValidationContextHolder.getTokenValidationContext();
		JwtToken token = tokenValidationContext.getJwtToken(RESTSTS_ISSUER);
		validateStsToken(token, authorizationHeader);
		validateRequestedScope(token, scope);
	}

	private void validateRequestedScope(JwtToken token, String scope) {
		if (!SCOPE_PATTERN.matcher(scope).matches()) {
			throw new RestStsTokenExchangeException("Requested scope has invalid format!");
		}
		if (dokAuraProxyProperties.subjectScopeMap().get(token.getSubject()) == null) {
			throw new RestStsTokenExchangeException("Subject is null!");
		}
		if (!dokAuraProxyProperties.subjectScopeMap().get(token.getSubject()).contains(scope)) {
			throw new RestStsTokenExchangeException("Subject is not authorized for requested scope " + scope);
		}
	}

	private void validateStsToken(String authorizationHeader) {
		TokenValidationContext tokenValidationContext = tokenValidationContextHolder.getTokenValidationContext();
		JwtToken token = tokenValidationContext.getJwtToken(RESTSTS_ISSUER);
		validateStsToken(token, authorizationHeader);
	}

	private void validateStsToken(JwtToken token, String authorizationHeader) {
		if (authorizationHeader != null && token != null) {
			populateMDCFromToken(token);
		} else {
			throw new RestStsTokenExchangeException("Unable to successfully validate RestSTS token");
		}
	}

	private void populateMDCFromToken(JwtToken token) {
		String consumerId = token.getSubject();
		MDC.put(MDC_CONSUMER_ID, consumerId);
		MDC.put(MDC_USER_ID, consumerId);
		MDC.put(MDC_USER_NAME, consumerId);
	}

	static class RestStsTokenExchangeException extends RuntimeException {
		public RestStsTokenExchangeException(String message) {
			super(message);
		}
	}
}

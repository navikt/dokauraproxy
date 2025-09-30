package no.nav.dokauraproxy.dokauraproxy;

public record TokenResponse(
		String access_token,
		String token_type,
		String expires_in,
		String error
) {
}

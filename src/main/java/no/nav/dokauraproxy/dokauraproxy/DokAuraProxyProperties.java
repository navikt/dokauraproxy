package no.nav.dokauraproxy.dokauraproxy;

import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("dokauraproxy")
@Validated
public record DokAuraProxyProperties(
		@NotEmpty String targetScope
) {
}

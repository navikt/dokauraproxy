package no.nav.dokauraproxy.dokauraproxy;

import no.nav.security.token.support.spring.test.EnableMockOAuth2Server;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("itest")
@SpringBootTest
@EnableMockOAuth2Server
class DokAuraProxyApplicationTests {

	@Test
	void contextLoads() {
	}

}

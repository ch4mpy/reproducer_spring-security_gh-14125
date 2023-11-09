package com.c4soft.spring_security.issues;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest()
@AutoConfigureWebTestClient
@Import(TestSecurityConf.class)
class ReproducerBffReactiveApplicationTests {

	private static final Instant iat = Instant.ofEpochSecond(1699405149);
	private static final Instant exp = Instant.ofEpochSecond(1699465149);
	private static final OidcIdToken ch4mpIdToken =
			new OidcIdToken("test.id.token", iat, exp, Map.of("exp", exp.getEpochSecond(), "preferred_username", "ch4mpy", "sub", "123-456"));
	private static final OidcUser ch4mp = new DefaultOidcUser(List.of(), ch4mpIdToken, "preferred_username");

	@Autowired
	WebTestClient api;

	@Test
	void givenCsrfTokenIsMissing_whenLogout_thenForbidden() {
		api.mutateWith(SecurityMockServerConfigurers.mockOidcLogin().oidcUser(ch4mp)).post().uri("/logout").exchange().expectStatus().isForbidden();
	}

	@Test
	void givenCsrfTokenIsPresent_whenLogout_thenOk() {
		api
				.mutateWith(SecurityMockServerConfigurers.mockOidcLogin().oidcUser(ch4mp))
				.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri("/logout")
				.exchange()
				.expectStatus()
				.isAccepted()
				.expectHeader()
				.location("/login?logout");
	}

}

package com.c4soft.spring_security.issues;

import static org.hamcrest.CoreMatchers.is;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4soft.spring_security.issues.MeController.UserDto;

@WebFluxTest(controllers = MeController.class)
@Import({ TestSecurityConf.class, WebSecurityConfig.class })
class MeControllerTest {

	private static final Instant iat = Instant.ofEpochSecond(1699405149);
	private static final Instant exp = Instant.ofEpochSecond(1699465149);
	private static final OidcIdToken ch4mpIdToken =
			new OidcIdToken("test.id.token", iat, exp, Map.of("exp", exp.getEpochSecond(), "preferred_username", "ch4mpy", "sub", "123-456"));
	private static final OidcUser ch4mp = new DefaultOidcUser(List.of(), ch4mpIdToken, "preferred_username");

	@Autowired
	WebTestClient api;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGetMe_thenOk() {
		api.get().uri("/me").exchange().expectStatus().isOk().expectBody(UserDto.class).value(is(UserDto.ANONYMOUS));
	}

	@Test
	@WithAnonymousUser
	void givenUserIsCh4mp_whenGetMe_thenOk() {
		api
				.mutateWith(SecurityMockServerConfigurers.mockOidcLogin().oidcUser(ch4mp))
				.get()
				.uri("/me")
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody(UserDto.class)
				.value(is(new UserDto(ch4mpIdToken.getSubject(), ch4mp.getName(), List.of(), exp.getEpochSecond())));
	}

}

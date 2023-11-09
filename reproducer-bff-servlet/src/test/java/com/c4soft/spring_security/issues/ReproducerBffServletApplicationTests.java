package com.c4soft.spring_security.issues;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest()
@AutoConfigureMockMvc
@Import(TestSecurityConf.class)
class ReproducerBffServletApplicationTests {

	private static final Instant iat = Instant.ofEpochSecond(1699405149);
	private static final Instant exp = Instant.ofEpochSecond(1699465149);
	private static final OidcIdToken ch4mpIdToken =
			new OidcIdToken("test.id.token", iat, exp, Map.of("exp", exp.getEpochSecond(), "preferred_username", "ch4mpy", "sub", "123-456"));
	private static final OidcUser ch4mp = new DefaultOidcUser(List.of(), ch4mpIdToken, "preferred_username");

	@Autowired
	MockMvc api;

	@Test
	@WithAnonymousUser
	void givenCsrfTokenIsMissing_whenLogout_thenForbidden() throws Exception {
		api.perform(post("/logout").with(SecurityMockMvcRequestPostProcessors.oidcLogin().oidcUser(ch4mp))).andExpect(status().isForbidden());
	}

	@Test
	void givenCsrfTokenIsPresent_whenLogout_thenOk() throws Exception {
		api
				.perform(
						post("/logout")
								.with(SecurityMockMvcRequestPostProcessors.oidcLogin().oidcUser(ch4mp))
								.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isAccepted());
	}

}

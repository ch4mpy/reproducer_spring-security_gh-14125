package com.c4soft.spring_security.issues;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.WebFilter;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

	@Bean
	SecurityWebFilterChain clientSecurityFilterChain(
			ServerHttpSecurity http,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			@Value("${spa-uri:http://localhost:4200/}") String spaUri)
			throws Exception {
		http.oauth2Login(login -> {
			login.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler(spaUri));
			login.authenticationFailureHandler(new RedirectServerAuthenticationFailureHandler(spaUri));
		});
		http.logout(logout -> {
			logout.logoutSuccessHandler(new SpaLogoutSucessHandler(clientRegistrationRepository, spaUri));
		});
		http.cors(cors -> cors.configurationSource(corsConfigurationSource(spaUri)));

		http.csrf(csrf -> {
			csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse());
			csrf.csrfTokenRequestHandler(new XorServerCsrfTokenRequestAttributeHandler()::handle);
		});

		http.authorizeExchange(ex -> ex.pathMatchers("/login/**", "/oauth2/**", "/me").permitAll().anyExchange().authenticated());

		return http.build();
	}

	@Bean
	WebFilter csrfCookieWebFilter() {
		return (exchange, chain) -> {
			exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty()).subscribe();
			return chain.filter(exchange);
		};
	}

	@Component
	static class KeycloakRealmGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {

		@SuppressWarnings("unchecked")
		@Override
		public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			authorities.forEach(authority -> {
				if (authority instanceof OAuth2UserAuthority user) {
					final var realmAccess = (Map<String, Object>) user.getAttributes().getOrDefault("realm_access", Map.of());
					final var roles = (List<String>) realmAccess.getOrDefault("roles", List.of());
					mappedAuthorities.addAll(roles.stream().map(SimpleGrantedAuthority::new).toList());
				}
			});

			return mappedAuthorities;
		};
	}

	UrlBasedCorsConfigurationSource corsConfigurationSource(String spaUri) {
		final var configuration = new CorsConfiguration();
		configuration.setAllowedMethods(Arrays.asList("*"));
		configuration.setAllowedOriginPatterns(Arrays.asList(spaUri));
		
		final var source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	static class SpaLogoutSucessHandler implements ServerLogoutSuccessHandler {
		private final OidcClientInitiatedServerLogoutSuccessHandler delegate;

		public SpaLogoutSucessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository, String postLogoutRedirectUri) {
			this.delegate = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
			this.delegate.setPostLogoutRedirectUri(postLogoutRedirectUri);
		}

		@Override
		public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			return delegate.onLogoutSuccess(exchange, authentication).then(Mono.fromRunnable(() -> {
				exchange.getExchange().getResponse().setStatusCode(HttpStatus.ACCEPTED);
			}));
		}

	}
}

package com.c4soft.spring_security.issues;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

	@Bean
	SecurityFilterChain clientSecurityFilterChain(
			HttpSecurity http,
			ClientRegistrationRepository clientRegistrationRepository,
			@Value("${spa-uri:http://localhost:4200/}") String spaUri)
			throws Exception {
		http.oauth2Login(login -> {
			login.loginPage("/oauth2/authorization/login");
			login.defaultSuccessUrl(spaUri, true);
			login.failureUrl(spaUri);
		});
		http.logout(logout -> {
			logout.logoutSuccessHandler(new SpaLogoutSucessHandler(clientRegistrationRepository, spaUri));
		});
		http.cors(cors -> cors.configurationSource(corsConfigurationSource(spaUri)));

		http.csrf(csrf -> {
			csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
			csrf.csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler()::handle);
		});
		http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);

		http.authorizeHttpRequests(requests -> requests.requestMatchers("/login/**", "/oauth2/**", "/me").permitAll().anyRequest().authenticated());

		return http.build();
	}

	/**
	 * https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_a_single_page_application_with_cookiecsrftokenrepository
	 */
	private static final class CsrfCookieFilter extends OncePerRequestFilter {

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
				throws ServletException,
				IOException {
			CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
			// Render the token value to a cookie by causing the deferred token to be loaded
			csrfToken.getToken();

			filterChain.doFilter(request, response);
		}

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

	static class SpaLogoutSucessHandler implements LogoutSuccessHandler {
		private final OidcClientInitiatedLogoutSuccessHandler delegate;

		public SpaLogoutSucessHandler(ClientRegistrationRepository clientRegistrationRepository, String postLogoutRedirectUri) {
			this.delegate = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
			this.delegate.setPostLogoutRedirectUri(postLogoutRedirectUri);
			delegate.setRedirectStrategy((HttpServletRequest request, HttpServletResponse response, String url) -> {
				response.setHeader(HttpHeaders.LOCATION, url);
				response.setStatus(HttpStatus.ACCEPTED.value());
			});
		}

		@Override
		public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
			delegate.onLogoutSuccess(request, response, authentication);
		}

	}
}

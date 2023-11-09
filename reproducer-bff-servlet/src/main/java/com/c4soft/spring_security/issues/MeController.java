package com.c4soft.spring_security.issues;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController {

	@GetMapping("/me")
	public UserDto getMe(Authentication auth) {
		if (auth instanceof OAuth2AuthenticationToken oauth2 && oauth2.getPrincipal() instanceof OidcUser oidc) {
			return new UserDto(
					oidc.getSubject(),
					oauth2.getName(),
					oauth2.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(),
					oidc.getExpiresAt().getEpochSecond());
		}
		return UserDto.ANONYMOUS;
	}

	static record UserDto(String subject, String username, List<String> roles, Long exp) {
		static final UserDto ANONYMOUS = new UserDto("", "", List.of(), Long.MAX_VALUE);
	}

}

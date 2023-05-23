package com.kerneldc.keycloakclient.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private KeycloakJwtRolesConverter keycloakJwtRolesConverter;
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

		DelegatingJwtGrantedAuthoritiesConverter authoritiesConverter =
				// Using the delegating converter multiple converters can be combined
				new DelegatingJwtGrantedAuthoritiesConverter(
						// First add the default converter
						new JwtGrantedAuthoritiesConverter(),
						// Second add our custom Keycloak specific converter
						keycloakJwtRolesConverter);

		// Set up http security to use the JWT converter defined above
		httpSecurity.oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(jwt -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt), keycloakJwtRolesConverter.getUsername(jwt)));

		//return httpSecurity.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().permitAll())
				// .authorizeRequests(authorizeRequests ->
				// authorizeRequests.anyRequest().authenticated())
				// .authorizeRequests(authorizeRequests ->
				// authorizeRequests.anyRequest().hasRole("kerneldc-realm-user-role"))
				// .authorizeRequests(authorizeRequests ->
				// authorizeRequests.anyRequest().hasRole("SCOPE_PROFILE"))

		httpSecurity.authorizeRequests()
		.mvcMatchers("/sandboxController/noBearerTokenPing", "/actuator/*").permitAll()
		.mvcMatchers("/protected/sandboxController/getUserInfo").hasRole("realm_sso-app-user-role")
		//.mvcMatchers("/noBearerTokenPing").hasRole("realm_sso2-app-admin-role")
		;

		httpSecurity.exceptionHandling(
						exception -> exception.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
								.accessDeniedHandler(new BearerTokenAccessDeniedHandler()))

				.cors().and().csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		
		return httpSecurity.build();
	}

}

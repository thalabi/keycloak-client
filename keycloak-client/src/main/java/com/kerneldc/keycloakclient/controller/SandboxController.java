package com.kerneldc.keycloakclient.controller;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class SandboxController {
	
private record UserInfo(String username, String firstName, String lastName, String email, List<String> roles, List<String> backEndAuthorities) {};

	@GetMapping(path = "/protected/sandboxController/ping")
	public UserInfo UserInfo() {
		if (SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof Jwt) {
			
			var jwtAuthenticationToken= (JwtAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();
			LOGGER.info("jwtAuthenticationToken: {}" ,jwtAuthenticationToken);
			LOGGER.info("jwtAuthenticationToken.name: {}" ,jwtAuthenticationToken.getName());
			
			var jwt = (Jwt)jwtAuthenticationToken.getPrincipal();
			LOGGER.info("jwt id: {}, claims: {}", jwt.getId(), jwt.getClaims());
			for (Entry<String, Object> entry : jwt.getClaims().entrySet()) {
				LOGGER.info("jwt, {} = {}", entry.getKey(), entry.getValue());
				
			}
			Map<String, List<String>> realmAccess = jwt.getClaim("realm_access");
			var roles = realmAccess.get("roles");
			roles.sort(null);

			var authorities = jwtAuthenticationToken.getAuthorities();
			var backEndAuthorities = authorities.stream().map(auth -> auth.getAuthority()).collect(Collectors.toList());
			backEndAuthorities.sort(null);
			
			var userInfo = new UserInfo(jwt.getClaims().get("preferred_username").toString(),
					jwt.getClaims().get("given_name").toString(), jwt.getClaims().get("family_name").toString(),
					jwt.getClaims().get("email").toString(), roles, backEndAuthorities);
			LOGGER.info("userInfo: {}", userInfo);
			
			return userInfo;
		} else {
			return new UserInfo("", "","","", List.of(""), List.of(""));
		}
	}

	@GetMapping(path = "/sandboxController/noBearerTokenPing")
	public String noBearerTokenPing() {
		if (SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof Jwt) {
			var jwt = (Jwt)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
			LOGGER.info(jwt.getClaims().toString()+(new Date()));
			var response =  "{\"noBearerTokenPing\": \""+SecurityContextHolder.getContext().getAuthentication().getAuthorities()+"\"}";
			LOGGER.info(response);
			return response;
		} else {
			return "{\"noBearerTokenPing\": \"pong\"}";
		}
	}
}

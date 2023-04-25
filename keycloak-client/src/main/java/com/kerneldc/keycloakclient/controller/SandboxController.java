package com.kerneldc.keycloakclient.controller;

import java.util.Date;
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
	
	//private  securityContext;

	@GetMapping(path = "ping")
	public String ping() {
		if (SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof Jwt) {
			var jwt = (Jwt)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
			LOGGER.info("jwt id: {}, claims: {}", jwt.getId(), jwt.getClaims());
			
			
			var jwtAuthenticationToken= (JwtAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();
			LOGGER.info("jwtAuthenticationToken: {}" ,jwtAuthenticationToken);
			LOGGER.info("jwtAuthenticationToken.name: {}" ,jwtAuthenticationToken.getName());
			var jwt2 = (Jwt)jwtAuthenticationToken.getPrincipal();
			LOGGER.info("jwt2 id: {}, claims: {}", jwt2.getId(), jwt2.getClaims());
			var authorities = jwtAuthenticationToken.getAuthorities();
			var authortiesList = authorities.stream().map(auth -> auth.getAuthority()).collect(Collectors.toList());
			authortiesList.sort(null);
			var username = jwtAuthenticationToken.getName();
			LOGGER.info("username: {}", username);
			var response =  "{\"ping-authortiesList\": \""+authortiesList+"\", \"ping-username\": \""+username+"\"}";
			LOGGER.info("reponse: {}" ,response);
			
			return response;
		} else {
			return "{\"ping\": \"pong\"}";
		}
	}

	@GetMapping(path = "noBearerTokenPing")
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

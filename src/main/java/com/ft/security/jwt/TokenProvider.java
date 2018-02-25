package com.ft.security.jwt;

import io.github.jhipster.config.JHipsterProperties;

import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@Component
public class TokenProvider {

	private final Logger log = LoggerFactory.getLogger(TokenProvider.class);

	private static final String AUTHORITIES_KEY = "auth";

	private String secretKey;

	private long tokenValidityInMilliseconds;

	private long tokenValidityInMillisecondsForRememberMe;

	private final JHipsterProperties jHipsterProperties;

	private Algorithm algorithm;

	private JWTVerifier verifier;

	public TokenProvider(JHipsterProperties jHipsterProperties) {
		this.jHipsterProperties = jHipsterProperties;
	}

	@PostConstruct
	public void init() throws Exception {
		this.secretKey = jHipsterProperties.getSecurity().getAuthentication().getJwt().getSecret();

		this.tokenValidityInMilliseconds = 1000
				* jHipsterProperties.getSecurity().getAuthentication().getJwt().getTokenValidityInSeconds();
		this.tokenValidityInMillisecondsForRememberMe = 1000 * jHipsterProperties.getSecurity().getAuthentication()
				.getJwt().getTokenValidityInSecondsForRememberMe();
		// OAUTH0
		this.algorithm = Algorithm.HMAC512(this.secretKey);
		this.verifier = JWT.require(algorithm)
				// .withIssuer("auth0")
				.build();
	}

	public String createToken(Authentication authentication, boolean rememberMe) {
		String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(","));
		log.debug("Authorities", authorities);
		long now = (new Date()).getTime();
		Date validity;
		if (rememberMe) {
			validity = new Date(now + this.tokenValidityInMillisecondsForRememberMe);
		} else {
			validity = new Date(now + this.tokenValidityInMilliseconds);
		}
		// OAUTH2
		return JWT.create().withSubject(authentication.getName()).withClaim(AUTHORITIES_KEY, authorities)
				.withExpiresAt(validity)
				// .withIssuer("auth0")
				.sign(algorithm);
	}

	public Authentication getAuthentication(String token) {
		try {
			DecodedJWT claims = verifier.verify(token);
			log.debug("claims" + claims);

			Collection<? extends GrantedAuthority> authorities = Arrays
					.stream(claims.getClaim(AUTHORITIES_KEY).asString().split(",")).map(SimpleGrantedAuthority::new)
					.collect(Collectors.toList());
			log.debug("Authorities" + authorities);
			User principal = new User(claims.getSubject(), "", authorities);

			return new UsernamePasswordAuthenticationToken(principal, token, authorities);
		} catch (Exception e) {
			log.error("Failed to authenticate", e);
		}
		return null;
	}
}

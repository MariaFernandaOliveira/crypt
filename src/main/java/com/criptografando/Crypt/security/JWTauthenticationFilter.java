package com.criptografando.Crypt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.criptografando.Crypt.data.DataUserDetails;
import com.criptografando.Crypt.model.UserModel;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

public class JWTauthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public static final int TOKEN_EXPIRATION = 600_000;
    public static final String TOKEN_PASSWORD = "1da6fb56-c784-413d-a9e0-c4860b8570ea";

    private final AuthenticationManager authenticationManager;

    public JWTauthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try {
            UserModel userModel = new ObjectMapper().readValue(request.getInputStream(), UserModel.class);

            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    userModel.getLogin(),
                    userModel.getPassword(),
                    new ArrayList<>()
            ));

        } catch (IOException e) {
            throw new RuntimeException("Authentication error", e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        DataUserDetails userDetails = (DataUserDetails) authResult.getPrincipal();

        String token = JWT.create().
                withSubject(userDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION))
                .sign(Algorithm.HMAC512(TOKEN_PASSWORD));

        response.getWriter().write(token);
        response.getWriter().flush();

    }

    //adicionar na dependencia auth0
    //responsavel por autenticar o usuario e fazer a geração do token
}

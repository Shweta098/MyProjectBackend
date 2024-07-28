package com.app.filters;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class RequestValidationBeforeFilter implements Filter{
	
	
	public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";
    private Charset credentialsCharset = StandardCharsets.UTF_8;
    
  //This filter will be executed for only login time, that's why authorization token starts wih Basic
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest)request;
		HttpServletResponse res = (HttpServletResponse)response;
		String header = req.getHeader(AUTHORIZATION);
		if(header!=null) {
			header = header.trim();
			if(StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
				byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8); // t=remove bsic and space from header
                byte[] decoded;
                try {
                	//decode the token and check for email
                	decoded = Base64.getDecoder().decode(base64Token);
                	String token = new String(decoded, credentialsCharset);
                	int delim = token.indexOf(":");
                	if(delim==-1)
                		throw new BadCredentialsException("Invalid basic authenticaton token");
                	String email = token.substring(0, delim);
                	if(email.toLowerCase().contains("test")) {
                		res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                		return;
                	}
                }catch (IllegalArgumentException e) {
                    throw new BadCredentialsException("Failed to decode basic authentication token");
                }
			}
		}
		chain.doFilter(request, response);
	}

}

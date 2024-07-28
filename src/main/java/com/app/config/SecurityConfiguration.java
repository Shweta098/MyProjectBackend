package com.app.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import com.app.filters.CsrfCookieFilter;
import com.app.filters.JwtTokenGenerationFilter;
import com.app.filters.JwtTokenValidatorFilter;
import com.app.filters.RequestValidationBeforeFilter;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
public class SecurityConfiguration {
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
		CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
		requestHandler.setCsrfRequestAttributeName("_csrf");
		
		//tell spring secuiryt not to create session and we are managing sesison creating
		http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
		.cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
			@Override
			public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
				CorsConfiguration config = new CorsConfiguration();
				config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
				config.setAllowedMethods(Collections.singletonList("*")); //get or post
				config.setAllowCredentials(true); //we are fine to accept credentials to and from the application
				config.setAllowedHeaders(Collections.singletonList("*"));
				//now as we are sending custom header to UI application, we need to tell UI to accept the header,
				//otherwise the UI will not accept the header
				//While using CSRF token we did not need to configure it because csrf token was configured by framework and framework handles it
				config.setExposedHeaders(Arrays.asList("Authorization"));
				config.setMaxAge(3600L);
				return config;
			}
		}))
		.csrf((csrf)->csrf.csrfTokenRequestHandler(requestHandler)
				.ignoringRequestMatchers("/register", "/contact") // as /notices method is get request spring security does not provide csrf protection, so don't need to ignore
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())) //The method withHttpOnlyFalse allows angular to read XSRF cookie 
		.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
		.addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
		// Here, either BasicAuthenticationFilter class could be executed first or AuthoritiesLoggingAtFilter could be executed first. SO, we should be careful while using this filter
		.addFilterAfter(new JwtTokenGenerationFilter(), BasicAuthenticationFilter.class)
		.addFilterBefore(new JwtTokenValidatorFilter(), BasicAuthenticationFilter.class)
		.authorizeHttpRequests((requests)->requests
				//used in case of authority:
				/*.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
				.requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT","VIEWBALANCE")
				.requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
				.requestMatchers("/myCards").hasAuthority("VIEWCARDS")*/
				//used in case of roles:
				.requestMatchers("/myAccount").hasAnyRole("USER")
				.requestMatchers("/myBalance").hasAnyRole("USER","ADMIN")
				.requestMatchers("/myLoans").authenticated()
				.requestMatchers("/myCards").hasRole("USER")
				.requestMatchers("/user").authenticated()
				.requestMatchers("/notices","/register", "/contact").permitAll())
			.formLogin(Customizer.withDefaults()) // request coming through http form or UI app
			.httpBasic(Customizer.withDefaults()); // REST api as http basic standards
		return http.build();
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		//return NoOpPasswordEncoder.getInstance(); //To save password in plain text format (not recommended)
		return new BCryptPasswordEncoder();
	}

}

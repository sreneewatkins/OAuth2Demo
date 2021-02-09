package com.tts.Oauth2Demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

/*
We want users to be able to view the homepage without being logged in.
We'll use WebSecurityConfigurerAdapter, which configures the security filter
chain that carries the OAuth 2.0 authentication processor.
 */

@SpringBootApplication
@RestController
public class Oauth2DemoApplication extends WebSecurityConfigurerAdapter {

	/*
	To start, let's make a /user endpoint in our main class. Edit
	OAuth2Demo.application.java. This will send back the currently logged-in user.
	Include RestController and set up the mapping.
	 */
	@GetMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
//		return Collections.singletonMap("name", principal.getAttribute("name"));
		return Collections.singletonMap("login", principal.getAttribute("login"));
	}

	/*
	we'll configure our HttpSecurity.
	You want to allow:
	/ since that’s the page you just made dynamic, with some of its content visible
	to unauthenticated users
	/error since that’s a Spring Boot endpoint for displaying errors, and
	Everything, including /user remains secure unless indicated because of the
	.anyRequest().authenticated() configuration at the end.
	Finally, since we are interfacing with the backend over Ajax, we’ll want to
	configure endpoints to respond with a 401 (i.e. user isn't logged in), instead
	of the default behavior of redirecting to a login page.
	Configuring the authenticationEntryPoint achieves this for us.
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests(a -> a
						.antMatchers("/", "/error").permitAll()
						.anyRequest().authenticated()
				)
				.exceptionHandling(e -> e
						.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
				)
				.oauth2Login().defaultSuccessUrl("/", true)
			/*
			Next, we need to add an endpoint in our OAuth2Demo.java file. The changes come after
			the .oauth2Login().defaultSuccessUrl("/", true). What did we do? We routed logout request
			to /logout, reroute to /, and then clear the information about the user from local storage.
			 */
				.and()
				.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				.logoutSuccessUrl("/").deleteCookies("JSESSIONID")
				.invalidateHttpSession(true);
	}

	public static void main(String[] args) {

		SpringApplication.run(Oauth2DemoApplication.class, args);
	}

}

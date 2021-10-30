package com.phunq.springsecurityjwt.security;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import com.phunq.springsecurityjwt.filter.CustomAuthenticationFilter;
import com.phunq.springsecurityjwt.filter.CustomAuthorizationFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final UserDetailsService userDetailsService;
  private final PasswordEncoder passwordEncoder;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/api/whoami").permitAll()
        .antMatchers("/login**").permitAll()
        .antMatchers("/api/login/**").permitAll()
        .antMatchers("/api/token/refresh/**").permitAll()
        .antMatchers(GET, "/api/users**").hasAuthority("ROLE_USER")
        .antMatchers(POST, "/api/users**").hasAuthority("ROLE_ADMIN")
        .anyRequest().authenticated();

    http.sessionManagement().sessionCreationPolicy(STATELESS);

    http
        .csrf().disable()
        .headers().disable();

    CustomAuthenticationFilter customerAuthenticationFilter =
        new CustomAuthenticationFilter(authenticationManagerBean());
    customerAuthenticationFilter.setFilterProcessesUrl("/api/login");
    http.addFilter(customerAuthenticationFilter);

    CustomAuthorizationFilter customAuthorizationFilter =
        new CustomAuthorizationFilter();
    http.addFilterBefore(customAuthorizationFilter, CustomAuthenticationFilter.class);

  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
        .userDetailsService(userDetailsService)
        .passwordEncoder(passwordEncoder);
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }
}

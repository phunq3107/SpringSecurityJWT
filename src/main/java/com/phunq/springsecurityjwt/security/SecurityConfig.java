package com.phunq.springsecurityjwt.security;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import com.phunq.springsecurityjwt.filter.CustomAuthenticationFilter;
import com.phunq.springsecurityjwt.filter.CustomAuthorizationFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final AuthenticationProvider authenticationProvider;

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
        new CustomAuthenticationFilter(authenticationProvider);
    customerAuthenticationFilter.setFilterProcessesUrl("/api/login");
    http.addFilter(customerAuthenticationFilter);

    CustomAuthorizationFilter customAuthorizationFilter =
        new CustomAuthorizationFilter();
    http.addFilterBefore(customAuthorizationFilter, CustomAuthenticationFilter.class);

  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(authenticationProvider);
  }

//  @Bean
//  @Override
//  public AuthenticationManager authenticationManagerBean() throws Exception {
//    return super.authenticationManagerBean();
//  }


}

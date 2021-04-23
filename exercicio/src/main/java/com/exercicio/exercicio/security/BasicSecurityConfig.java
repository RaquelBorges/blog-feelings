package com.exercicio.exercicio.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService userDetailService; // injeção de dependencia de uma
													// classe que existe dentro de websecurity

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailService);
	}

	@Bean
	public PasswordEncoder passwordEnconder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()

				/*
				 * .antMatchers("/usuarios/logar").permitAll() //libera end point sem token
				 * .antMatchers("/usuarios/cadastrar").permitAll()//libera end point sem token
				 */
				.antMatchers("/**").permitAll().antMatchers("/usuarios/logar").permitAll()// liberar alguns caminhos do
																							// meu controller para o
																							// client não precisar de
																							// tokens e tenha acesso
				.antMatchers("/usuarios/cadastrar").permitAll()// tanto cadastrar quanto logar serão liberados dentro da
																// API
				.antMatchers(HttpMethod.GET, "/postagens").permitAll().antMatchers(HttpMethod.GET, "/tema").permitAll()
				.anyRequest().authenticated() // todas as outras requisições deverão ser autenticadas
				.and().httpBasic().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // não
																													// guarda
																													// sessão
				.and().cors().and().csrf().disable();
	}

}

package com.quipux.detecciones.login.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.quipux.detecciones.login.Jwt.JwtAuthenticationFilter;

import static com.quipux.detecciones.login.User.Permission.ADMIN_CREATE;
import static com.quipux.detecciones.login.User.Permission.ADMIN_DELETE;
import static com.quipux.detecciones.login.User.Permission.ADMIN_READ;
import static com.quipux.detecciones.login.User.Permission.ADMIN_UPDATE;
import static com.quipux.detecciones.login.User.Permission.USER_CREATE;
import static com.quipux.detecciones.login.User.Permission.USER_DELETE;
import static com.quipux.detecciones.login.User.Permission.USER_READ;
import static com.quipux.detecciones.login.User.Permission.USER_UPDATE;
import static com.quipux.detecciones.login.User.Role.ADMIN;
import static com.quipux.detecciones.login.User.Role.USER;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
@RequiredArgsConstructor
@EnableReactiveMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        // return http
        //     .csrf(csrf -> 
        //         csrf
        //         .disable())
        //     .authorizeHttpRequests(authRequest ->
              
        //     authRequest
              
        //        //.requestMatchers("/v2/api-docs", "/configuration/ui", "/swagger-resources/**", "/configuration/**", "/swagger-ui.html", "/webjars/**").permitAll()

        //         .requestMatchers("/auth/**").permitAll()
        //         .requestMatchers("/api/detecciones/**").hasAnyRole(ADMIN.name(),USER.name())
                
        //         .requestMatchers("/api/v1/user/**").hasAnyRole(ADMIN.name(),USER.name())
                
        //         .requestMatchers(GET,"/api/detecciones").hasAnyAuthority(ADMIN_READ.name(),USER_READ.name())
        //         .requestMatchers(PUT,"/api/detecciones").hasAnyAuthority(ADMIN_READ.name(),USER_READ.name())

        //         .requestMatchers(GET,"/api/v1/user/**").hasAnyAuthority(ADMIN_READ.name(),USER_READ.name())
        //         .requestMatchers(POST,"/api/v1/user/**").hasAnyAuthority(ADMIN_CREATE.name(),USER_CREATE.name())
        //         .requestMatchers(PUT,"/api/v1/user/**").hasAnyAuthority(ADMIN_UPDATE.name(),USER_UPDATE.name())
        //        .requestMatchers(DELETE,"/api/v1/user/**").hasAnyAuthority(ADMIN_DELETE.name(),USER_DELETE.name())
                
        //         .requestMatchers("/api/v1/admin/**").hasAnyRole(ADMIN.name())
                
        //        .requestMatchers(GET,"/api/v1/admin/**").hasAnyAuthority(ADMIN_READ.name())
        //         .requestMatchers(POST,"/api/v1/admin/**").hasAnyAuthority(ADMIN_CREATE.name())
        //         .requestMatchers(PUT,"/api/v1/admin/**").hasAnyAuthority(ADMIN_UPDATE.name())
        //        .requestMatchers(DELETE,"/api/v1/admin/**").hasAnyAuthority(ADMIN_DELETE.name())
        //        .anyRequest().authenticated()
        //         )
        //     .sessionManagement(sessionManager->
        //         sessionManager 
        //           .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        //     .authenticationProvider(authProvider)
        //     .addFilterAt(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        //     .build();
            

        return http
                .authenticationEntryPoint((swe, e) -> 
                    Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED))
                ).accessDeniedHandler((swe, e) -> 
                    Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN))
                ).and()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .pathMatchers("/login").permitAll()
                .anyExchange().authenticated()
                .and().build();

            
    }

    


}

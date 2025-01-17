package guru.sfg.brewery.config;

import guru.sfg.brewery.security.JpaUserDetailsService;
import guru.sfg.brewery.security.RestHeaderAuthFilter;
import guru.sfg.brewery.security.RestUrlAuthFilter;
import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager authenticationManager) {
        RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    public RestUrlAuthFilter restUrlAuthFilter(AuthenticationManager authenticationManager) {
        RestUrlAuthFilter filter = new RestUrlAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(restHeaderAuthFilter(authenticationManager()),
                UsernamePasswordAuthenticationFilter.class)
                .csrf().disable();

        http.addFilterBefore(restUrlAuthFilter(authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class);

        http
            .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() //do not use in production!
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                })
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();

        //h2 console config
        http.headers().frameOptions().sameOrigin();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        //return NoOpPasswordEncoder.getInstance();
        //return new LdapShaPasswordEncoder();
        //return new StandardPasswordEncoder();
        //return new BCryptPasswordEncoder();
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //@Autowired
    //JpaUserDetailsService jpaUserDetailsService;

    //@Override
    //protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //auth.userDetailsService(this.jpaUserDetailsService).passwordEncoder(passwordEncoder());


        /*auth.inMemoryAuthentication()
                .withUser("spring")
                //.password("guru")
                //.password("{SSHA}wj1dq3l7C7RCIxyehITzochuT30VljBjY3Kvmw==")
                //.password("0aa6b69ed729181be9302f0010fb3c6ce0b79de6c8a9ae55df791a540ef962ca72e6bf0186247d08")
                //.password("$2a$10$Q5oUTeI/4OrokjGrNAHZtON2Mr.hhHIiIqM4Td34d3T8bLzKTNrQm")
                .password("{bcrypt}$2a$10$M12PunNQSnCS.W9U2EsCVewi2hYtUti3UpQ4.d4/NoyYINBU3p9bi")
                .roles("ADMIN")
                .and()
                .withUser("user")
                //.password("password")
                //.password("{SSHA}wj1dq3l7C7RCIxyehITzochuT30VljBjY3Kvmw==")
                //.password("0aa6b69ed729181be9302f0010fb3c6ce0b79de6c8a9ae55df791a540ef962ca72e6bf0186247d08")
                //.password("$2a$10$Q5oUTeI/4OrokjGrNAHZtON2Mr.hhHIiIqM4Td34d3T8bLzKTNrQm")
                .password("{sha256}1a0339dada522a13d2d4a0daf9796d99adf200172bf8e6d17a64d20e480203397701d800c7f2dbfe")
                .roles("USER");
        auth.inMemoryAuthentication().withUser("scott")
                //.password("tiger")
                //.password("{ldap}{SSHA}Awt8sO+1+BJvq7m0YTopr5ibnUZWIsmQGtDnHA==")
                .password("{bcrypt10}$2a$10$TV9JuBJLkPFY.P7oYBREg.VyZtsAznf3NR8.l2S04pKp1ay/ERO8e")
                .roles("CUSTOMER");*/
    //}

    /*    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("spring")
                .password("guru")
                .roles("ADMIN")
                .build();
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }*/
}

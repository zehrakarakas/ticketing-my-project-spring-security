package com.cydeo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfig {
//*****HARD CODE WE NEED TO MODIFICATION******
//   @Bean
//   public UserDetailsService userDetailsService(PasswordEncoder encoder) {
//
//      List<UserDetails> userList = new ArrayList<>();
//      userList.add(new User("mike", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));
//      userList.add(new User("ozzy", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER"))));
//      return new InMemoryUserDetailsManager(userList);
//   }

   @Bean  //this bean for authorization//we can see our login page directly if we dont use we first see spring security login page
   public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      return http
              .authorizeRequests()  //whenever we run our security we need to authorize which page
              //.antMatchers("/user/**").hasRole("ADMIN")
              .antMatchers("/user/**").hasAuthority("Admin") //we use this becouse we need to match db (ROLE_)  hasAuthority not include Role_
              .antMatchers("/project/**").hasAuthority("Manager")
              .antMatchers("/task/employee/**").hasAuthority("Employee")//(bildigimiz endpoint burdaki / lar)
              .antMatchers("/task/**").hasAuthority("Manager")//certain role can see certain page (exp:admin only able to see /user pages)
              //.antMatchers("/project/**").hasRole("MANAGER")
              //.antMatchers("/task/employee/**").hasRole("EMPLOYEE")
             // .antMatchers("/task/**").hasRole("MANAGER")
              //.antMatchers("/task/**").hasAnyRole("EMPLOYEE","ADMIN")//more then any role (.hasAnyRole or .hasAnyAuthority)
              //.antMatchers("/task/**").hasAuthority("ROLE_EMPLOYEE")
              .antMatchers(//related with pages (controller or director)(5 line everybody access this 5 end pont)
                      "/",
                      "/login",
                      "/fragments/**",
                      "/assets/**",
                      "/images/**"   //** meaning everything
              ).permitAll()   //make it avaible for everyone
              .anyRequest().authenticated()  //antMaathchers disindakiler icin
              .and()
         //     .httpBasic() //spring give us one pop-up box
              .formLogin()//we create a own login page
                 .loginPage("/login")//representation of my login page //this gonna give us view
                 .defaultSuccessUrl("/welcome")//login information succesfully done(whenever user authotaticated with correct username and password)
                 .failureUrl("/login?error=true")//if user put the wrong information
                 .permitAll()  //should be accessible for everyone
              .and().build();

   }

   }


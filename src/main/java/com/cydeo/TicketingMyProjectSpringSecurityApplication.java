package com.cydeo;

import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootApplication
public class TicketingMyProjectSpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(TicketingMyProjectSpringSecurityApplication.class, args);
    }
    @Bean
    public ModelMapper mapper(){

        return new ModelMapper();
    }
    @Bean //for encoded
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();//it takes password and change to the encoded structure
    }



}

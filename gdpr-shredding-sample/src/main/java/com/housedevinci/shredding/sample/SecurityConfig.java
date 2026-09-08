package com.housedevinci.shredding.sample;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * L7. The erasure endpoint takes {@code requestedBy} from the authenticated principal ({@code
 * CustomerEndpoints.erase}), never from the request body, so it has to be authenticated for that to
 * mean anything. One user, HTTP Basic, the same shape module B's sample uses: this is a copyable
 * reference, not a real authorization model.
 */
@Configuration
class SecurityConfig {

  @Bean
  SecurityFilterChain security(HttpSecurity http) throws Exception {
    return http.csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(
            a -> a.requestMatchers("/customers/erasures").authenticated().anyRequest().permitAll())
        .httpBasic(Customizer.withDefaults())
        .build();
  }

  @Bean
  InMemoryUserDetailsManager users() {
    return new InMemoryUserDetailsManager(
        User.withUsername("dpo").password("{noop}dpo").roles("DPO").build());
  }
}

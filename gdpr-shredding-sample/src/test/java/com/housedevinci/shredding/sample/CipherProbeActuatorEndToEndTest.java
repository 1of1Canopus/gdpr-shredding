package com.housedevinci.shredding.sample;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * L8. {@code CipherProbeActuatorTest} in the starter calls the {@code SanitizingFunction} bean
 * directly; it never asserts that Boot actually applies that function to a live {@code /env} or
 * {@code /configprops} response. This stands up the sample with those two endpoints exposed - off
 * by default in {@code application.yml}, turned on here only - and reads them for real.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Testcontainers
@DirtiesContext
class CipherProbeActuatorEndToEndTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String MASTER_KEY_PLAINTEXT = "actuator-probe-master-key-32-byte";
  private static final String MASTER_KEY_BASE64 =
      Base64.getEncoder().encodeToString(MASTER_KEY_PLAINTEXT.getBytes(StandardCharsets.UTF_8));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    // S-25: pinned rather than resolved from the container's bootstrap connection.
    registry.add(
        "spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
    registry.add("shredding.master-key", () -> MASTER_KEY_BASE64);
    registry.add(
        "shredding.erasure-log.hmac-secret",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "actuator-probe-chain-secret-32by".getBytes(StandardCharsets.UTF_8)));
    registry.add(
        "shredding.blind-index.hmac-secret",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "actuator-probe-index-secret-32by".getBytes(StandardCharsets.UTF_8)));
    // Off by default in application.yml; turned on for this test only, to prove the sanitiser
    // works on the live endpoint rather than trusting that it is never reachable.
    registry.add("management.endpoints.web.exposure.include", () -> "health,info,env,configprops");
  }

  @Autowired MockMvc mockMvc;

  @Test
  void the_master_key_is_absent_from_the_live_env_endpoint() throws Exception {
    String body =
        mockMvc
            .perform(get("/actuator/env"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(StandardCharsets.UTF_8);

    assertThat(body).doesNotContain(MASTER_KEY_PLAINTEXT).doesNotContain(MASTER_KEY_BASE64);
    assertThat(body)
        .as("the property must still be listed, sanitised, not silently dropped")
        .contains("shredding.master-key");
  }

  @Test
  void the_master_key_is_absent_from_the_live_configprops_endpoint() throws Exception {
    String body =
        mockMvc
            .perform(get("/actuator/configprops"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(StandardCharsets.UTF_8);

    assertThat(body).doesNotContain(MASTER_KEY_PLAINTEXT).doesNotContain(MASTER_KEY_BASE64);
  }
}

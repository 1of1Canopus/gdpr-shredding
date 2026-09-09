package com.housedevinci.shredding.sample;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureChainVerifier;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * L4. Control 12 asks for "the sample ships a log-scan test grepping for the plaintext fixture".
 * {@code ShreddedFieldsDoNotLeakTest} is an ArchUnit/reflection test over the class structure and
 * never actually logs anything; {@code probe_entity_tostring_leaks_the_decrypted_value} inspects
 * {@code toString()} directly. Neither captures what the application actually wrote to its logs.
 * This attaches a real output capture to the end-to-end flow - create, read, erase, a failed write,
 * a subject-immutability refusal - and greps what was captured for the plaintext fixture.
 */
@SpringBootTest
@Testcontainers
@DirtiesContext
@ExtendWith(OutputCaptureExtension.class)
class LogScanTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add(
        "shredding.master-key",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "log-scan-test master key, 32byte".getBytes(StandardCharsets.UTF_8)));
    registry.add(
        "shredding.erasure-log.hmac-secret",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "log-scan-test chain secret, 32by".getBytes(StandardCharsets.UTF_8)));
    registry.add(
        "shredding.blind-index.hmac-secret",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "log-scan-test index secret, 32by".getBytes(StandardCharsets.UTF_8)));
  }

  @Autowired CustomerService service;
  @Autowired ErasureChainVerifier verifier;

  private static final String EMAIL = "leak-scan-fixture@example.com";
  private static final String PHONE = "+33199999999";

  @Test
  void the_captured_log_never_contains_the_plaintext_fixture(CapturedOutput output) {
    String customerId = "cust-logscan-" + System.nanoTime();
    service.create("acme", customerId, EMAIL, PHONE);
    service.byCustomerId(customerId);
    service.findByEmail("acme", EMAIL);
    service.erase("acme", customerId, "dpo", "art 17");
    service.byCustomerId(customerId);
    verifier.verify();

    // a failed write and a refused immutability change, both of which log at WARN elsewhere in
    // this suite - exercised here too, since a log line from an error path is exactly as
    // dangerous as one from the happy path
    try {
      service.create("acme", customerId, EMAIL, PHONE);
    } catch (RuntimeException ignored) {
      // expected: the subject is erased
    }

    // L14: a logging misconfiguration that captured nothing at all would otherwise read as a pass
    // for the two doesNotContain assertions below - they are vacuously true over an empty
    // capture. Assert the capture actually observed something this flow is known to log first:
    // ShreddingStartupCheck's own start-up line, benign and always emitted once per context.
    assertThat(output.getAll())
        .as("the output capture observed nothing at all - it is not proving anything below")
        .isNotEmpty()
        .contains("shredded field(s)");

    assertThat(output.getAll())
        .as("the application log must never contain a shredded field's plaintext value")
        .doesNotContain(EMAIL)
        .doesNotContain(PHONE);
  }
}

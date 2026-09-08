package com.housedevinci.shredding.sample;

import com.housedevinci.shredding.application.ErasureChainVerifier;
import java.security.Principal;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Four endpoints: create, read, erase, verify the erasure log.
 *
 * <p>L7: the read path takes the tenant explicitly - control 15 makes it mandatory and forbids a
 * default, and a copyable sample that looks it up by {@code customerId} alone teaches the wrong
 * habit. The erasure endpoint is behind HTTP Basic ({@code SecurityConfig}) and takes {@code
 * requestedBy} from the authenticated principal, never from the request body: a body field is
 * whatever the caller says it is, and the erasure log's {@code requestedBy} column is meant to be
 * an audit fact, not user input. See {@code README.md} for the one-line version of this note.
 */
@RestController
@RequestMapping("/customers")
public class CustomerEndpoints {

  private final CustomerService service;
  private final ErasureChainVerifier verifier;

  public CustomerEndpoints(CustomerService service, ErasureChainVerifier verifier) {
    this.service = service;
    this.verifier = verifier;
  }

  public record CreateRequest(String tenantId, String customerId, String email, String phone) {}

  public record CustomerView(String customerId, String email, String phone, boolean erased) {}

  public record EraseRequest(String tenantId, String customerId, String reason) {}

  public record EraseView(
      String outcome,
      int keysDestroyed,
      int blindIndexColumnsCleared,
      String completeInBackupsAt) {}

  @PostMapping
  public CustomerView create(@RequestBody CreateRequest request) {
    return view(
        service.create(request.tenantId(), request.customerId(), request.email(), request.phone()));
  }

  @GetMapping("/{tenantId}/{customerId}")
  public ResponseEntity<List<CustomerView>> read(
      @PathVariable String tenantId, @PathVariable String customerId) {
    List<CustomerView> views =
        service.byTenantAndCustomerId(tenantId, customerId).stream()
            .map(CustomerEndpoints::view)
            .toList();
    return views.isEmpty() ? ResponseEntity.notFound().build() : ResponseEntity.ok(views);
  }

  @PostMapping("/erasures")
  public EraseView erase(@RequestBody EraseRequest request, Principal principal) {
    var result =
        service.erase(
            request.tenantId(), request.customerId(), principal.getName(), request.reason());
    return new EraseView(
        result.outcome().name(),
        result.keysDestroyed(),
        result.blindIndexColumnsCleared(),
        result.completeInBackupsAt().toString());
  }

  @GetMapping("/erasures/verify")
  public ErasureChainVerifier.Report verify() {
    return verifier.verify();
  }

  private static CustomerView view(Customer customer) {
    return new CustomerView(
        customer.getCustomerId(),
        customer.getEmail(),
        customer.getPhone(),
        CustomerService.isErased(customer));
  }
}

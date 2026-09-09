package com.housedevinci.shredding.autoconfigure.composite;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TicketRepository extends JpaRepository<Ticket, Ticket.Key> {
  List<Ticket> findByOwnerId(String ownerId);
}

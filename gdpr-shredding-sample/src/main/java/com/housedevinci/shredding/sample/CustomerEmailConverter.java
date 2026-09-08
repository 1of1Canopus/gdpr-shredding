package com.housedevinci.shredding.sample;

import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Converter;

/** Binds Customer.email into the AAD. One class per shredded field; see QUESTIONS #1. */
@Converter
public class CustomerEmailConverter extends ShreddedStringConverter {

  public CustomerEmailConverter() {
    super("Customer", "email");
  }
}

package com.housedevinci.shredding.sample;

import com.housedevinci.shredding.jpa.ShreddedStringConverter;
import jakarta.persistence.Converter;

/** Binds Customer.phone into the AAD. */
@Converter
public class CustomerPhoneConverter extends ShreddedStringConverter {

  public CustomerPhoneConverter() {
    super("Customer", "phone");
  }
}

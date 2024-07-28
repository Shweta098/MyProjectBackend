package com.app.repositories;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.app.pojo.Contact;


@Repository
public interface ContactRepository extends JpaRepository<Contact, Long> {
	
	
}

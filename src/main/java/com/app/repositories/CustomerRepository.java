package com.app.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.app.pojo.Customer;

public interface CustomerRepository extends JpaRepository<Customer, Integer>{
	
	List<Customer> findByEmail(String email);

}

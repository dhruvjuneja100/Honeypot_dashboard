package com.honeypot.dashboard.repository;

import com.honeypot.dashboard.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AlertRepository extends JpaRepository<Alert, Long> {
    List<Alert> findAllByOrderByTimestampDesc();
}

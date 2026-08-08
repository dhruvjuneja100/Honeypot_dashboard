package com.honeypot.dashboard.repository;

import com.honeypot.dashboard.model.AttackLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AttackLogRepository extends JpaRepository<AttackLog, Long> {
    int countByIpAddressAndTimestampAfter(String ipAddress, LocalDateTime timestamp);
    int countByIpAddressAndEndpointAndTimestampAfter(String ipAddress, String endpoint, LocalDateTime timestamp);

    // NOTE: Spring Data JPA (the version pulled in by Spring Boot 3.2.3) does not
    // reliably convert aliased @Query projections into List<Map<String,Object>> -
    // that conversion is not guaranteed for plain JPQL/native @Query methods and
    // throws a ClassCastException/ConverterNotFoundException at runtime.
    // Returning Object[] rows is the well-supported, version-safe approach; the
    // rows are converted into List<Map<String,Object>> in AnalyticsService.
    @Query("SELECT a.attackType, COUNT(a) FROM AttackLog a GROUP BY a.attackType")
    List<Object[]> countAttacksByType();

    @Query(value = "SELECT ip_address, COUNT(*) AS cnt FROM attack_logs GROUP BY ip_address ORDER BY cnt DESC LIMIT 10", nativeQuery = true)
    List<Object[]> findTop10Ips();

    @Query("SELECT a.country, a.city, COUNT(a) FROM AttackLog a WHERE a.country IS NOT NULL GROUP BY a.country, a.city")
    List<Object[]> countGeoDistribution();
}

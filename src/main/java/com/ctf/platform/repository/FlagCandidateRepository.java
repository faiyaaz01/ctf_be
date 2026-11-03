package com.ctf.platform.repository;

import com.ctf.platform.model.FlagCandidate;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FlagCandidateRepository extends MongoRepository<FlagCandidate, String> {
    List<FlagCandidate> findByUserIdOrderByUpdatedAtDesc(String userId);
    Optional<FlagCandidate> findByUserIdAndValue(String userId, String value);
    void deleteByUserId(String userId);
}

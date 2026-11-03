package com.ctf.platform.repository;

import com.ctf.platform.model.Challenge;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ChallengeRepository extends MongoRepository<Challenge, String> {
    List<Challenge> findByActiveTrue();
    List<Challenge> findByCategoryAndActiveTrue(String category);
}

package com.ctf.platform.controller;

import com.ctf.platform.model.Announcement;
import com.ctf.platform.model.Challenge;
import com.ctf.platform.model.User;
import com.ctf.platform.repository.AnnouncementRepository;
import com.ctf.platform.repository.ChallengeRepository;
import com.ctf.platform.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ChallengeController {

    private final ChallengeRepository challengeRepository;
    private final AnnouncementRepository announcementRepository;
    private final UserRepository userRepository;

    // ── CHALLENGES ────────────────────────────────────────────────
    @GetMapping("/challenges")
    public ResponseEntity<List<Challenge>> getChallenges() {
        return ResponseEntity.ok(challengeRepository.findByActiveTrue());
    }

    @PostMapping("/challenges")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Challenge> createChallenge(@RequestBody Challenge challenge) {
        return ResponseEntity.ok(challengeRepository.save(challenge));
    }

    @PostMapping("/challenges/{id}/submit")
    public ResponseEntity<?> submitFlag(
            @PathVariable String id,
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Login required to submit flags"));
        }

        Challenge challenge = challengeRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Challenge not found"));

        String submittedFlag = body.getOrDefault("flag", "").trim();

        if (challenge.getFlag() != null && challenge.getFlag().equals(submittedFlag)) {
            User user = userRepository.findByUsername(userDetails.getUsername()).orElseThrow();
            if (!challenge.getSolvedByUsers().contains(user.getId())) {
                challenge.getSolvedByUsers().add(user.getId());
                challenge.setSolveCount(challenge.getSolveCount() + 1);
                challengeRepository.save(challenge);

                user.setScore(user.getScore() + challenge.getPoints());
                user.setSolvesCount(user.getSolvesCount() + 1);
                userRepository.save(user);
            }
            return ResponseEntity.ok(Map.of("status", "success", "message", "Correct flag!"));
        } else {
            return ResponseEntity.ok(Map.of("status", "error", "message", "Incorrect flag, try again"));
        }
    }

    // ── ANNOUNCEMENTS ─────────────────────────────────────────────
    @GetMapping("/announcements")
    public ResponseEntity<List<Announcement>> getAnnouncements() {
        return ResponseEntity.ok(announcementRepository.findAllByOrderByCreatedAtDesc());
    }

    @PostMapping("/announcements")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Announcement> createAnnouncement(@RequestBody Announcement announcement) {
        return ResponseEntity.ok(announcementRepository.save(announcement));
    }
}

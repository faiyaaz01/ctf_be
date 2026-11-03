package com.ctf.platform.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "challenges")
public class Challenge {

    @Id
    private String id;

    private String title;

    private String category; // Crypto, Web, Forensics, Reverse, Pwn, OSINT

    private String description;

    @Builder.Default
    private int points = 100;

    private String flag; // stored or hashed

    @Builder.Default
    private List<String> hints = new ArrayList<>();

    @Builder.Default
    private List<String> solvedByUsers = new ArrayList<>();

    @Builder.Default
    private int solveCount = 0;

    @Builder.Default
    private boolean active = true;

    @CreatedDate
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;
}

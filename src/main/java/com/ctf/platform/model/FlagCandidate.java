package com.ctf.platform.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "flag_candidates")
public class FlagCandidate {

    @Id
    private String id;

    @Indexed
    private String userId;

    private String value;

    @Indexed
    private String sourceTool;

    @Builder.Default
    private String confidence = "medium"; // low, medium, high

    @Builder.Default
    private List<String> sources = new ArrayList<>();

    @Builder.Default
    private boolean confirmed = false;

    @Builder.Default
    private boolean falsePositive = false;

    @CreatedDate
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;
}

package com.sandeep.eventrabackend.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * Records one attendee's votes on a live poll so each attendee can vote at
 * most once per poll (unique {@code poll_id + user_id}). Single-select polls
 * record the chosen option in {@code optionText}; multi-select polls store the
 * full set of chosen options in {@code options} ({@code optionText} keeps the
 * first selection for backward compatibility).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "live_audience_poll_votes",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_lapv_poll_user",
                columnNames = {"poll_id", "user_id"}))
public class LiveAudiencePollVote {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "poll_id", nullable = false)
    private Long pollId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "option_text", nullable = false, length = 200)
    private String optionText;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "live_audience_poll_vote_options",
            joinColumns = @JoinColumn(name = "poll_vote_id"))
    @Column(name = "option_text", length = 200)
    private Set<String> options = new HashSet<>();

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
}

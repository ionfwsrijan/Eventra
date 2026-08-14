package com.sandeep.eventrabackend.repository;

import com.sandeep.eventrabackend.model.LiveAudiencePollVote;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface LiveAudiencePollVoteRepository extends JpaRepository<LiveAudiencePollVote, Long> {

    Optional<LiveAudiencePollVote> findByPollIdAndUserId(Long pollId, Long userId);
}

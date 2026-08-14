package com.sandeep.eventrabackend.zkp;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/zkp")
@CrossOrigin(origins = "*")
public class ZkVerificationController {

    private final ZkRangeVerifierService verifierService;

    public ZkVerificationController(ZkRangeVerifierService verifierService) {
        this.verifierService = verifierService;
    }

    public static class ZkProofRequest {
        private String commitment;
        private String proofValue; // Representing verified status range value
        private String salt;
        private Long minValue;
        private Long maxValue;

        public String getCommitment() { return commitment; }
        public void setCommitment(String commitment) { this.commitment = commitment; }

        public String getProofValue() { return proofValue; }
        public void setProofValue(String proofValue) { this.proofValue = proofValue; }

        public String getSalt() { return salt; }
        public void setSalt(String salt) { this.salt = salt; }

        public Long getMinValue() { return minValue; }
        public void setMinValue(Long minValue) { this.minValue = minValue; }

        public Long getMaxValue() { return maxValue; }
        public void setMaxValue(Long maxValue) { this.maxValue = maxValue; }
    }

    @PostMapping("/verify-range")
    public ResponseEntity<Map<String, Object>> verifyRangeProof(@RequestBody ZkProofRequest request) {
        if (request.getMinValue() == null || request.getMaxValue() == null) {
            Map<String, Object> badRequest = new HashMap<>();
            badRequest.put("verified", false);
            badRequest.put("piiExposed", false);
            badRequest.put("attestationStatus", "RANGE_BOUNDS_REQUIRED");
            badRequest.put("message", "minValue and maxValue are required for range verification");
            return ResponseEntity.badRequest().body(badRequest);
        }

        boolean isValid = verifierService.verifyRangeProof(
                request.getCommitment(),
                request.getProofValue(),
                request.getSalt(),
                request.getMinValue(),
                request.getMaxValue()
        );

        Map<String, Object> response = new HashMap<>();
        response.put("verified", isValid);
        response.put("piiExposed", false);
        response.put("attestationStatus", isValid ? "VERIFIED_ELIGIBLE" : "VERIFICATION_FAILED");

        return ResponseEntity.ok(response);
    }
}

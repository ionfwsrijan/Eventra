package com.sandeep.eventrabackend.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Request payload for redeeming a password reset token")
public class ConfirmPasswordResetRequest {

    @NotBlank(message = "Reset token is required")
    @Schema(description = "Raw password reset token delivered to the account owner", example = "r7Jd2...")
    private String token;

    @NotBlank(message = "New password is required")
    @Size(min = 8, message = "New password must be at least 8 characters")
    @Schema(description = "New password (min 8 characters)", example = "MyNewSecret@123")
    private String newPassword;
}

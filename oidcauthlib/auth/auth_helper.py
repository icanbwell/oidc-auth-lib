import base64
import json
import logging

from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class AuthHelper:
    @staticmethod
    def encode_state(content: dict[str, str | None]) -> str:
        """
        Encode the state content into a base64url encoded string.

        Args:
            content: The content to encode, typically a dictionary.

        Returns:
            A base64url encoded string of the content.
        """
        json_content = json.dumps(content)
        encoded_content = base64.urlsafe_b64encode(json_content.encode("utf-8")).decode(
            "utf-8"
        )
        return encoded_content.rstrip("=")

    @staticmethod
    def decode_state(encoded_content: str) -> dict[str, str | None]:
        """
        Decode a base64url encoded string back into its original dictionary form.

        Args:
            encoded_content: The base64url encoded string to decode.

        Returns:
            The decoded content as a dictionary.
        """
        # Add padding if necessary
        try:
            if not encoded_content or not isinstance(encoded_content, str):
                logger.error("Failed to decode state: Input is empty or not a string")
                raise ValueError("Encoded state is empty or not a string")
            # Fix base64 padding
            padding_needed = (-len(encoded_content)) % 4
            padded_content = encoded_content + ("=" * padding_needed)
            try:
                json_content = base64.urlsafe_b64decode(padded_content).decode("utf-8")
            except Exception as e:
                logger.error(f"Failed to decode state (base64 error): {e}")
                raise ValueError("Invalid base64 encoding in state") from e
            try:
                result = json.loads(json_content)
            except Exception as e:
                logger.error(f"Failed to decode state (JSON error): {e}")
                raise ValueError("Invalid JSON in decoded state") from e
            if not isinstance(result, dict):
                logger.error(
                    "Failed to decode state: Decoded state is not a dictionary"
                )
                raise ValueError("Decoded state is not a dictionary")
            return result
        except Exception:
            # Already logged specific error above
            raise

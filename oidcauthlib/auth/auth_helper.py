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
        padding_needed = (-len(encoded_content)) % 4
        padded_content = encoded_content + ("=" * padding_needed)
        try:
            json_content = base64.urlsafe_b64decode(padded_content).decode("utf-8")
            result = json.loads(json_content)
            if not isinstance(result, dict):
                raise ValueError("Decoded state is not a dictionary")
            return result
        except Exception as e:
            logger.error(f"Failed to decode state: {e}")
            raise ValueError("Invalid encoded state") from e

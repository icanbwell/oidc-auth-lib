import urllib.parse


class MongoUrlHelpers:
    @staticmethod
    def add_credentials_to_mongo_url(
        *, mongo_url: str, username: str | None, password: str | None
    ) -> str:
        """
        Adds username and password to a MongoDB connection string.
        Args:
            mongo_url (str): Original MongoDB connection string (e.g., 'mongodb://mongo:27017?appName=fhir-server')
            username (str): MongoDB username
            password (str): MongoDB password
        Returns:
            str: Updated connection string with credentials
        """

        if not username or not password:
            return mongo_url

        # Parse the URL
        parsed = urllib.parse.urlparse(mongo_url)
        # URL-encode username and password
        encoded_username = urllib.parse.quote_plus(username)
        encoded_password = urllib.parse.quote_plus(password)
        # Build netloc with credentials
        if "@" in parsed.netloc:
            # Already has credentials, replace them
            host = parsed.netloc.split("@")[1]
        else:
            host = parsed.netloc
        netloc = f"{encoded_username}:{encoded_password}@{host}"
        # Reconstruct the URL
        new_url = urllib.parse.urlunparse(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        return new_url

    @staticmethod
    def extract_hostname(mongo_url: str) -> str:
        """
        Extracts the hostname(s) from a MongoDB connection string.
        Args:
            mongo_url (str): MongoDB connection string
        Returns:
            str: Hostname(s) portion of the connection string
        """
        parsed = urllib.parse.urlparse(mongo_url)
        # Remove credentials if present
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = netloc.split("@", 1)[1]
        # For replica sets, multiple hosts are comma-separated
        hosts = netloc.split(",")
        hostnames = []
        for h in hosts:
            h = h.strip()
            if h.startswith("["):
                # IPv6: extract up to closing bracket
                end = h.find("]")
                if end != -1:
                    hostnames.append(h[: end + 1])
                else:
                    hostnames.append(h)  # fallback
            else:
                # Regular hostname: split on ':'
                hostnames.append(h.split(":")[0])
        return ",".join(hostnames)

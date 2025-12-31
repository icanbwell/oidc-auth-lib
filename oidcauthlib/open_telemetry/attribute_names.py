class OidcOpenTelemetryAttributeNames:
    # Mongo/GridFS attributes
    DB_COLLECTION: str = "db.collection"
    STORAGE_KEY: str = "storage.key"
    STORAGE_HIT: str = "storage.hit"
    STORAGE_MODE: str = "storage.mode"

    # Auth/Well-known configuration attributes
    WELL_KNOWN_URI: str = "auth.well_known_uri"

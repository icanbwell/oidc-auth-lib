"""
Unit tests for AsyncMongoRepository using mongomock.
"""

import pytest
from bson import ObjectId
from typing import Optional, Any
import mongomock

from oidcauthlib.auth.repository.mongo.mongo_repository import AsyncMongoRepository
from oidcauthlib.auth.models.base_db_model import BaseDbModel


# Test model for testing
class TestModel(BaseDbModel):
    """Test model for repository testing."""

    name: str
    email: Optional[str] = None
    age: Optional[int] = None


class AsyncMongoMockClient:
    """Wrapper to make mongomock work with async/await syntax."""

    def __init__(self, connection_string: str = "mongodb://localhost:27017") -> None:
        self._sync_client: mongomock.MongoClient[Any] = mongomock.MongoClient(
            connection_string
        )

    def __getitem__(self, key: str) -> "AsyncMongoMockDatabase":
        """Get database by name."""
        db = self._sync_client[key]
        return AsyncMongoMockDatabase(db)

    def get_database(self, name: str) -> "AsyncMongoMockDatabase":
        return self[name]

    async def close(self) -> None:
        """Close the client connection."""
        self._sync_client.close()


class AsyncMongoMockDatabase:
    """Async wrapper for mongomock database."""

    def __init__(self, sync_db: Any) -> None:
        self._sync_db = sync_db

    def __getitem__(self, key: str) -> "AsyncMongoMockCollection":
        """Get collection by name."""
        collection = self._sync_db[key]
        return AsyncMongoMockCollection(collection)

    async def command(self, *args: Any, **kwargs: Any) -> Any:
        """Execute database command."""
        return self._sync_db.command(*args, **kwargs)


class AsyncMongoMockCollection:
    """Async wrapper for mongomock collection."""

    def __init__(self, sync_collection: Any) -> None:
        self._sync_collection = sync_collection

    async def insert_one(self, document: Any, **kwargs: Any) -> Any:
        """Insert a single document."""
        return self._sync_collection.insert_one(document, **kwargs)

    async def find_one(self, filter: Optional[Any] = None, **kwargs: Any) -> Any:
        """Find a single document."""
        return self._sync_collection.find_one(filter, **kwargs)

    def find(
        self, filter: Optional[Any] = None, **kwargs: Any
    ) -> "AsyncMongoMockCursor":
        """Return an async cursor."""
        cursor = self._sync_collection.find(filter, **kwargs)
        return AsyncMongoMockCursor(cursor)

    async def find_one_and_update(self, filter: Any, update: Any, **kwargs: Any) -> Any:
        """Find and update a document."""
        return self._sync_collection.find_one_and_update(filter, update, **kwargs)

    async def replace_one(self, filter: Any, replacement: Any, **kwargs: Any) -> Any:
        """Replace a document."""
        return self._sync_collection.replace_one(filter, replacement, **kwargs)

    async def delete_one(self, filter: Any, **kwargs: Any) -> Any:
        """Delete a single document."""
        return self._sync_collection.delete_one(filter, **kwargs)


class AsyncMongoMockCursor:
    """Async wrapper for mongomock cursor."""

    def __init__(self, sync_cursor: Any) -> None:
        self._sync_cursor = sync_cursor

    def limit(self, limit: int) -> "AsyncMongoMockCursor":
        """Limit the cursor results."""
        self._sync_cursor = self._sync_cursor.limit(limit)
        return self

    def skip(self, skip: int) -> "AsyncMongoMockCursor":
        """Skip results."""
        self._sync_cursor = self._sync_cursor.skip(skip)
        return self

    async def to_list(self, length: Optional[int] = None) -> list[Any]:
        """Convert cursor to list."""
        return list(self._sync_cursor)


# Provide fixture that returns async client and underlying sync client
@pytest.fixture
def mongo_clients() -> Any:
    async_client = AsyncMongoMockClient()
    sync_client = async_client._sync_client  # direct access for verification
    yield async_client, sync_client
    sync_client.close()


class TestAsyncMongoRepositoryInit:
    """Tests for AsyncMongoRepository initialization."""

    def test_init_with_valid_parameters(self, mongo_clients: Any) -> None:
        async_client, _ = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username="test_user",
            password="test_pass",
            client=async_client,
        )

        assert repo.database_name == "test_db"
        assert "test_user:test_pass" in repo.connection_string

    def test_init_without_credentials(self, mongo_clients: Any) -> None:
        async_client, _ = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        assert repo.database_name == "test_db"
        assert "mongodb://localhost:27017" in repo.connection_string

    def test_init_raises_error_with_empty_server_url(self) -> None:
        """Test repository raises ValueError when server_url is empty."""
        with pytest.raises(
            ValueError, match="MONGO_URL environment variable is not set"
        ):
            AsyncMongoRepository(
                server_url="",
                database_name="test_db",
                username=None,
                password=None,
            )

    def test_init_raises_error_with_empty_database_name(self) -> None:
        """Test repository raises ValueError when database_name is empty."""
        with pytest.raises(ValueError, match="Database name must be provided"):
            AsyncMongoRepository(
                server_url="mongodb://localhost:27017",
                database_name="",
                username=None,
                password=None,
            )


class TestAsyncMongoRepositoryConnection:
    """Tests for connection management."""

    @pytest.mark.asyncio
    async def test_connect_success(self, mongo_clients: Any) -> None:
        """Test successful connection to MongoDB."""
        async_client, _ = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # mongomock automatically supports the ping command
        await repo.connect()
        # If no exception is raised, the test passes

    @pytest.mark.asyncio
    async def test_connect_failure(self, mongo_clients: Any, monkeypatch: Any) -> None:
        """Test connection failure raises exception."""
        async_client, _ = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Monkeypatch the command method to raise an exception
        async def failing_command(*args: Any, **kwargs: Any) -> None:
            raise Exception("Connection failed")

        monkeypatch.setattr(repo._db, "command", failing_command)

        with pytest.raises(Exception, match="Connection failed"):
            await repo.connect()

    @pytest.mark.asyncio
    async def test_close_connection(self, mongo_clients: Any) -> None:
        """Test closing MongoDB connection."""
        async_client, _ = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # mongomock supports close()
        await repo.close()
        # If no exception is raised, the test passes


class TestAsyncMongoRepositoryInsert:
    """Tests for insert operations."""

    @pytest.mark.asyncio
    async def test_insert_success(self, mongo_clients: Any) -> None:
        """Test successful document insertion."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        model = TestModel(name="John Doe", email="john@example.com", age=30)
        result = await repo.insert("test_collection", model)

        assert result is not None
        assert isinstance(result, ObjectId)

        # Verify the document was inserted
        collection = sync_client["test_db"]["test_collection"]
        inserted_doc = collection.find_one({"_id": result})
        assert inserted_doc is not None
        assert inserted_doc["name"] == "John Doe"
        assert inserted_doc["email"] == "john@example.com"
        assert inserted_doc["age"] == 30

    @pytest.mark.asyncio
    async def test_insert_filters_none_values(self, mongo_clients: Any) -> None:
        """Test that None values are filtered out during insertion."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        model = TestModel(name="John Doe", email=None)
        result = await repo.insert("test_collection", model)

        # Verify the document was inserted without None values
        collection = sync_client["test_db"]["test_collection"]
        inserted_doc = collection.find_one({"_id": result})
        assert "email" not in inserted_doc
        assert "age" not in inserted_doc
        assert inserted_doc["name"] == "John Doe"


class TestAsyncMongoRepositoryFindById:
    """Tests for find_by_id operations."""

    @pytest.mark.asyncio
    async def test_find_by_id_success(self, mongo_clients: Any) -> None:
        """Test successful find by ID."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert a document first
        doc_id = ObjectId()
        sync_client["test_db"]["test_collection"].insert_one(
            {
                "_id": doc_id,
                "name": "John Doe",
                "email": "john@example.com",
                "age": 30,
            }
        )

        result = await repo.find_by_id("test_collection", TestModel, doc_id)

        assert result is not None
        assert result.name == "John Doe"
        assert result.email == "john@example.com"
        assert result.age == 30
        assert result.id == doc_id

    @pytest.mark.asyncio
    async def test_find_by_id_not_found(self, mongo_clients: Any) -> None:
        """Test find by ID returns None when document not found."""

        async_client, _ = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        result = await repo.find_by_id("test_collection", TestModel, ObjectId())

        assert result is None


class TestAsyncMongoRepositoryFindByFields:
    """Tests for find_by_fields operations."""

    @pytest.mark.asyncio
    async def test_find_by_fields_success(self, mongo_clients: Any) -> None:
        """Test successful find by fields."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert a document first
        doc_id = ObjectId()
        sync_client["test_db"]["test_collection"].insert_one(
            {
                "_id": doc_id,
                "name": "John Doe",
                "email": "john@example.com",
            }
        )

        result = await repo.find_by_fields(
            "test_collection",
            TestModel,
            {"email": "john@example.com"},
        )

        assert result is not None
        assert result.name == "John Doe"
        assert result.email == "john@example.com"

    @pytest.mark.asyncio
    async def test_find_by_fields_not_found(self, mongo_clients: Any) -> None:
        """Test find by fields returns None when no match."""

        async_client, _ = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        result = await repo.find_by_fields(
            "test_collection",
            TestModel,
            {"email": "nonexistent@example.com"},
        )

        assert result is None


class TestAsyncMongoRepositoryFindMany:
    """Tests for find_many operations."""

    @pytest.mark.asyncio
    async def test_find_many_success(self, mongo_clients: Any) -> None:
        """Test successful find many documents."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert test documents
        doc_id1 = ObjectId()
        doc_id2 = ObjectId()
        sync_client["test_db"]["test_collection"].insert_one(
            {"_id": doc_id1, "name": "John Doe", "email": "john@example.com"}
        )
        sync_client["test_db"]["test_collection"].insert_one(
            {"_id": doc_id2, "name": "Jane Doe", "email": "jane@example.com"}
        )

        results = await repo.find_many(
            "test_collection",
            TestModel,
            filter_dict={"name": {"$regex": "Doe"}},
            limit=10,
            skip=0,
        )

        assert len(results) == 2
        assert results[0].name == "John Doe"
        assert results[1].name == "Jane Doe"

    @pytest.mark.asyncio
    async def test_find_many_empty_results(self, mongo_clients: Any) -> None:
        """Test find many returns empty list when no matches."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        results = await repo.find_many("test_collection", TestModel)

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_find_many_with_default_filter(self, mongo_clients: Any) -> None:
        """Test find many with default empty filter."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert a document to verify empty filter returns all
        sync_client["test_db"]["test_collection"].insert_one(
            {"_id": ObjectId(), "name": "Test User"}
        )

        results = await repo.find_many("test_collection", TestModel, filter_dict=None)

        # Should return all documents when filter is None
        assert len(results) == 1
        assert results[0].name == "Test User"


class TestAsyncMongoRepositoryUpdateById:
    """Tests for update_by_id operations."""

    @pytest.mark.asyncio
    async def test_update_by_id_success(self, mongo_clients: Any) -> None:
        """Test successful update by ID."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert a document first
        doc_id = ObjectId()
        sync_client["test_db"]["test_collection"].insert_one(
            {
                "_id": doc_id,
                "name": "John Doe",
                "email": "john@example.com",
                "age": 30,
            }
        )

        update_model = TestModel(
            name="John Smith", email="john.smith@example.com", age=31
        )
        result = await repo.update_by_id(
            "test_collection", doc_id, update_model, TestModel
        )

        assert result is not None
        assert result.name == "John Smith"
        assert result.email == "john.smith@example.com"
        assert result.age == 31

        # Verify the document was actually updated
        updated_doc = sync_client["test_db"]["test_collection"].find_one(
            {"_id": doc_id}
        )
        assert updated_doc["name"] == "John Smith"
        assert updated_doc["email"] == "john.smith@example.com"
        assert updated_doc["age"] == 31

    @pytest.mark.asyncio
    async def test_update_by_id_not_found(self, mongo_clients: Any) -> None:
        """Test update by ID returns None when document not found."""
        async_client, _ = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        update_model = TestModel(name="John Smith")
        result = await repo.update_by_id(
            "test_collection", ObjectId(), update_model, TestModel
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_update_by_id_filters_none_values(self, mongo_clients: Any) -> None:
        """Test that None values are filtered out during update."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert a document first
        doc_id = ObjectId()
        sync_client["test_db"]["test_collection"].insert_one(
            {
                "_id": doc_id,
                "name": "John Doe",
                "email": "john@example.com",
                "age": 30,
            }
        )

        update_model = TestModel(name="John Smith", email=None)
        result = await repo.update_by_id(
            "test_collection", doc_id, update_model, TestModel
        )
        assert result is not None

        # Verify None values were filtered out - email should remain unchanged
        updated_doc = sync_client["test_db"]["test_collection"].find_one(
            {"_id": doc_id}
        )
        assert updated_doc["name"] == "John Smith"
        assert updated_doc["email"] == "john@example.com"  # Should remain unchanged
        assert "age" not in updated_doc or updated_doc.get("age") == 30


class TestAsyncMongoRepositoryDeleteById:
    """Tests for delete_by_id operations."""

    @pytest.mark.asyncio
    async def test_delete_by_id_success(self, mongo_clients: Any) -> None:
        """Test successful delete by ID."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert a document first
        doc_id = ObjectId()
        sync_client["test_db"]["test_collection"].insert_one(
            {
                "_id": doc_id,
                "name": "John Doe",
                "email": "john@example.com",
            }
        )

        result = await repo.delete_by_id("test_collection", doc_id)

        assert result is True
        # Verify the document was deleted
        assert (
            sync_client["test_db"]["test_collection"].find_one({"_id": doc_id}) is None
        )

    @pytest.mark.asyncio
    async def test_delete_by_id_not_found(self, mongo_clients: Any) -> None:
        """Test delete by ID returns False when document not found."""

        async_client, _ = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        result = await repo.delete_by_id("test_collection", ObjectId())

        assert result is False


class TestAsyncMongoRepositoryInsertOrUpdate:
    """Tests for insert_or_update operations."""

    @pytest.mark.asyncio
    async def test_insert_or_update_inserts_new_document(
        self, mongo_clients: Any
    ) -> None:
        """Test insert_or_update inserts new document when ID doesn't exist."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        model = TestModel(name="Jane Doe", email="jane@example.com", age=25)
        result = await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": "jane@example.com"},
        )

        assert result is not None
        assert isinstance(result, ObjectId)

        # Verify the document was inserted
        collection = sync_client["test_db"]["test_collection"]
        inserted_doc = collection.find_one({"_id": result})
        assert inserted_doc is not None
        assert inserted_doc["name"] == "Jane Doe"
        assert inserted_doc["email"] == "jane@example.com"
        assert inserted_doc["age"] == 25

    @pytest.mark.asyncio
    async def test_insert_or_update_updates_existing_document(
        self, mongo_clients: Any
    ) -> None:
        """Test insert_or_update updates when document exists."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert an existing document
        existing_id = ObjectId()
        collection = sync_client["test_db"]["test_collection"]
        collection.insert_one(
            {
                "_id": existing_id,
                "name": "John Doe",
                "email": "john@example.com",
            }
        )

        model = TestModel(name="John Smith", email="john@example.com", age=30)
        result = await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": "john@example.com"},
        )

        assert result == existing_id

        # Verify the document was updated
        updated_doc = collection.find_one({"_id": existing_id})
        assert updated_doc["name"] == "John Smith"
        assert updated_doc["age"] == 30

    @pytest.mark.asyncio
    async def test_insert_or_update_with_on_insert_callback(
        self, mongo_clients: Any
    ) -> None:
        """Test insert_or_update applies on_insert callback."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        def on_insert(item: TestModel) -> TestModel:
            item.age = 25  # Set default age on insert
            return item

        model = TestModel(name="John Doe", email="john@example.com")
        result = await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": "john@example.com"},
            on_insert=on_insert,
        )

        # Verify on_insert was applied
        collection = sync_client["test_db"]["test_collection"]
        inserted_doc = collection.find_one({"_id": result})
        assert inserted_doc["age"] == 25

    @pytest.mark.asyncio
    async def test_insert_or_update_with_on_update_callback(
        self, mongo_clients: Any
    ) -> None:
        """Test insert_or_update applies on_update callback."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert an existing document
        existing_id = ObjectId()
        collection = sync_client["test_db"]["test_collection"]
        collection.insert_one(
            {
                "_id": existing_id,
                "name": "John Doe",
                "email": "john@example.com",
                "age": 25,
            }
        )

        def on_update(item: TestModel) -> TestModel:
            item.age = 35  # Set age on update
            return item

        model = TestModel(name="John Smith", email="john@example.com")
        await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": "john@example.com"},
            on_update=on_update,
        )

        # Verify on_update was applied
        updated_doc = collection.find_one({"_id": existing_id})
        assert updated_doc["age"] == 35

    @pytest.mark.asyncio
    async def test_insert_or_update_no_modification(self, mongo_clients: Any) -> None:
        """Test insert_or_update with identical data (no modification needed)."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        # Insert an existing document
        existing_id = ObjectId()
        sync_client["test_db"]["test_collection"].insert_one(
            {
                "_id": existing_id,
                "name": "John Doe",
                "email": "john@example.com",
            }
        )

        # Update with same data (no actual modification)
        model = TestModel(name="John Doe", email=None)
        result = await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": "john@example.com"},
        )

        # Should still return the existing ID
        assert result == existing_id

    @pytest.mark.asyncio
    async def test_insert_or_update_insert_not_acknowledged(
        self, mongo_clients: Any
    ) -> None:
        """Test insert_or_update with mongomock - mongomock always acknowledges."""
        async_client, sync_client = mongo_clients
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
            client=async_client,
        )

        model = TestModel(name="John Doe", email="john@example.com")

        # With mongomock, inserts are always acknowledged, so this test
        # verifies that the operation completes successfully
        result = await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": "john@example.com"},
        )

        assert result is not None
        assert isinstance(result, ObjectId)


class TestAsyncMongoRepositoryHelperMethods:
    """Tests for helper methods."""

    def test_convert_model_to_dict(self) -> None:
        """Test _convert_model_to_dict converts model correctly."""
        model = TestModel(name="John Doe", email="john@example.com", age=30)
        result = AsyncMongoRepository._convert_model_to_dict(model)

        assert result["name"] == "John Doe"
        assert result["email"] == "john@example.com"
        assert result["age"] == 30
        # ID is not included when using default_factory (exclude_unset=True)
        assert "_id" not in result

    def test_convert_model_to_dict_with_objectid(self) -> None:
        """Test _convert_model_to_dict handles ObjectId correctly when explicitly set."""
        obj_id = ObjectId()
        model = TestModel(_id=obj_id, name="John Doe")
        result = AsyncMongoRepository._convert_model_to_dict(model)

        # When ID is explicitly set, it's included as 'id' (not '_id' since by_alias is not used)
        # The field_serializer converts ObjectId to string
        assert "id" in result
        assert result["id"] == str(obj_id)
        assert result["name"] == "John Doe"

    def test_convert_dict_to_model(self) -> None:
        """Test _convert_dict_to_model converts dict correctly."""
        doc_id = ObjectId()
        document = {
            "_id": doc_id,
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30,
        }

        result = AsyncMongoRepository._convert_dict_to_model(document, TestModel)

        assert isinstance(result, TestModel)
        assert result.name == "John Doe"
        assert result.email == "john@example.com"
        assert result.age == 30
        assert result.id == doc_id

    def test_convert_dict_to_model_with_mapping(self) -> None:
        """Test _convert_dict_to_model handles Mapping type correctly."""
        doc_id = ObjectId()
        # Use a dict as Mapping
        document: dict[str, Any] = {
            "_id": doc_id,
            "name": "Jane Doe",
            "email": "jane@example.com",
        }

        result = AsyncMongoRepository._convert_dict_to_model(document, TestModel)

        assert isinstance(result, TestModel)
        assert result.name == "Jane Doe"
        assert result.email == "jane@example.com"

    def test_convert_model_to_dict_objectid_serialization(self) -> None:
        """Test that ObjectId is serialized to string by field_serializer."""
        obj_id = ObjectId()
        model = TestModel(_id=obj_id, name="John Doe")
        result = AsyncMongoRepository._convert_model_to_dict(model)

        # The field_serializer should convert ObjectId to string automatically
        assert "id" in result
        assert isinstance(result["id"], str)
        assert result["id"] == str(obj_id)

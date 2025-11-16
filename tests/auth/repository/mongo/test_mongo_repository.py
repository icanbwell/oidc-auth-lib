"""
Unit tests for AsyncMongoRepository.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from bson import ObjectId
from pymongo.results import InsertOneResult, UpdateResult, DeleteResult
from typing import Optional, Any

from oidcauthlib.auth.repository.mongo.mongo_repository import AsyncMongoRepository
from oidcauthlib.auth.models.base_db_model import BaseDbModel


# Test model for testing
class TestModel(BaseDbModel):
    """Test model for repository testing."""

    name: str
    email: Optional[str] = None
    age: Optional[int] = None


class TestAsyncMongoRepositoryInit:
    """Tests for AsyncMongoRepository initialization."""

    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    def test_init_with_valid_parameters(self, mock_client: Mock) -> None:
        """Test repository initializes correctly with valid parameters."""
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username="test_user",
            password="test_pass",
        )

        assert repo.database_name == "test_db"
        assert "test_user:test_pass" in repo.connection_string
        mock_client.assert_called_once()

    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    def test_init_without_credentials(self, mock_client: Mock) -> None:
        """Test repository initializes correctly without credentials."""
        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        assert repo.database_name == "test_db"
        assert "mongodb://localhost:27017" in repo.connection_string
        mock_client.assert_called_once()

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
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_connect_success(self, mock_client: Mock) -> None:
        """Test successful connection to MongoDB."""
        mock_db = Mock()
        mock_db.command = AsyncMock(return_value={"ok": 1})
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        await repo.connect()
        mock_db.command.assert_called_once_with("ping")

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_connect_failure(self, mock_client: Mock) -> None:
        """Test connection failure raises exception."""
        mock_db = Mock()
        mock_db.command = AsyncMock(side_effect=Exception("Connection failed"))
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        with pytest.raises(Exception, match="Connection failed"):
            await repo.connect()

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_close_connection(self, mock_client: Mock) -> None:
        """Test closing MongoDB connection."""
        mock_client_instance = Mock()
        mock_client_instance.close = AsyncMock()
        mock_client_instance.__getitem__ = Mock(return_value=Mock())
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        await repo.close()
        mock_client_instance.close.assert_called_once()


class TestAsyncMongoRepositoryInsert:
    """Tests for insert operations."""

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_insert_success(self, mock_client: Mock) -> None:
        """Test successful document insertion."""
        inserted_id = ObjectId()
        mock_collection = Mock()
        mock_insert_result = Mock(spec=InsertOneResult)
        mock_insert_result.inserted_id = inserted_id
        mock_collection.insert_one = AsyncMock(return_value=mock_insert_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        model = TestModel(name="John Doe", email="john@example.com", age=30)
        result = await repo.insert("test_collection", model)

        assert result == inserted_id
        mock_collection.insert_one.assert_called_once()
        call_args = mock_collection.insert_one.call_args[0][0]
        assert call_args["name"] == "John Doe"
        assert call_args["email"] == "john@example.com"
        assert call_args["age"] == 30

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_insert_filters_none_values(self, mock_client: Mock) -> None:
        """Test that None values are filtered out during insertion."""
        inserted_id = ObjectId()
        mock_collection = Mock()
        mock_insert_result = Mock(spec=InsertOneResult)
        mock_insert_result.inserted_id = inserted_id
        mock_collection.insert_one = AsyncMock(return_value=mock_insert_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        model = TestModel(name="John Doe", email=None)
        await repo.insert("test_collection", model)

        call_args = mock_collection.insert_one.call_args[0][0]
        assert "email" not in call_args
        assert "age" not in call_args
        assert call_args["name"] == "John Doe"


class TestAsyncMongoRepositoryFindById:
    """Tests for find_by_id operations."""

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_find_by_id_success(self, mock_client: Mock) -> None:
        """Test successful find by ID."""
        doc_id = ObjectId()
        mock_document = {
            "_id": doc_id,
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30,
        }
        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=mock_document)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        result = await repo.find_by_id("test_collection", TestModel, doc_id)

        assert result is not None
        assert result.name == "John Doe"
        assert result.email == "john@example.com"
        assert result.age == 30
        assert result.id == doc_id

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_find_by_id_not_found(self, mock_client: Mock) -> None:
        """Test find by ID returns None when document not found."""
        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=None)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        result = await repo.find_by_id("test_collection", TestModel, ObjectId())

        assert result is None


class TestAsyncMongoRepositoryFindByFields:
    """Tests for find_by_fields operations."""

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_find_by_fields_success(self, mock_client: Mock) -> None:
        """Test successful find by fields."""
        doc_id = ObjectId()
        mock_document = {
            "_id": doc_id,
            "name": "John Doe",
            "email": "john@example.com",
        }
        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=mock_document)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        result = await repo.find_by_fields(
            "test_collection",
            TestModel,
            {"email": "john@example.com"},
        )

        assert result is not None
        assert result.name == "John Doe"
        assert result.email == "john@example.com"
        mock_collection.find_one.assert_called_once_with(
            filter={"email": "john@example.com"}
        )

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_find_by_fields_not_found(self, mock_client: Mock) -> None:
        """Test find by fields returns None when no match."""
        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=None)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
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
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_find_many_success(self, mock_client: Mock) -> None:
        """Test successful find many documents."""
        doc_id1 = ObjectId()
        doc_id2 = ObjectId()
        mock_documents = [
            {"_id": doc_id1, "name": "John Doe", "email": "john@example.com"},
            {"_id": doc_id2, "name": "Jane Doe", "email": "jane@example.com"},
        ]

        mock_cursor = Mock()
        mock_cursor.to_list = AsyncMock(return_value=mock_documents)
        mock_cursor.limit = Mock(return_value=mock_cursor)
        mock_cursor.skip = Mock(return_value=mock_cursor)

        mock_collection = Mock()
        mock_collection.find = Mock(return_value=mock_cursor)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
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
        mock_collection.find.assert_called_once_with({"name": {"$regex": "Doe"}})

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_find_many_empty_results(self, mock_client: Mock) -> None:
        """Test find many returns empty list when no matches."""
        mock_cursor = Mock()
        mock_cursor.to_list = AsyncMock(return_value=[])
        mock_cursor.limit = Mock(return_value=mock_cursor)
        mock_cursor.skip = Mock(return_value=mock_cursor)

        mock_collection = Mock()
        mock_collection.find = Mock(return_value=mock_cursor)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        results = await repo.find_many("test_collection", TestModel)

        assert len(results) == 0

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_find_many_with_default_filter(self, mock_client: Mock) -> None:
        """Test find many with default empty filter."""
        mock_cursor = Mock()
        mock_cursor.to_list = AsyncMock(return_value=[])
        mock_cursor.limit = Mock(return_value=mock_cursor)
        mock_cursor.skip = Mock(return_value=mock_cursor)

        mock_collection = Mock()
        mock_collection.find = Mock(return_value=mock_cursor)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        await repo.find_many("test_collection", TestModel, filter_dict=None)

        # Should call with empty dict when filter_dict is None
        mock_collection.find.assert_called_once_with({})


class TestAsyncMongoRepositoryUpdateById:
    """Tests for update_by_id operations."""

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_update_by_id_success(self, mock_client: Mock) -> None:
        """Test successful update by ID."""
        doc_id = ObjectId()
        updated_document = {
            "_id": doc_id,
            "name": "John Smith",
            "email": "john.smith@example.com",
            "age": 31,
        }

        mock_collection = Mock()
        mock_collection.find_one_and_update = AsyncMock(return_value=updated_document)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
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

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_update_by_id_not_found(self, mock_client: Mock) -> None:
        """Test update by ID returns None when document not found."""
        mock_collection = Mock()
        mock_collection.find_one_and_update = AsyncMock(return_value=None)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        update_model = TestModel(name="John Smith")
        result = await repo.update_by_id(
            "test_collection", ObjectId(), update_model, TestModel
        )

        assert result is None

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_update_by_id_filters_none_values(self, mock_client: Mock) -> None:
        """Test that None values are filtered out during update."""
        doc_id = ObjectId()
        updated_document = {
            "_id": doc_id,
            "name": "John Smith",
        }

        mock_collection = Mock()
        mock_collection.find_one_and_update = AsyncMock(return_value=updated_document)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        update_model = TestModel(name="John Smith", email=None)
        await repo.update_by_id("test_collection", doc_id, update_model, TestModel)

        # Check that $set was called with filtered values
        call_args = mock_collection.find_one_and_update.call_args
        set_data = call_args[0][1]["$set"]
        assert "email" not in set_data
        assert set_data["name"] == "John Smith"


class TestAsyncMongoRepositoryDeleteById:
    """Tests for delete_by_id operations."""

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_delete_by_id_success(self, mock_client: Mock) -> None:
        """Test successful delete by ID."""
        mock_result = Mock(spec=DeleteResult)
        mock_result.deleted_count = 1

        mock_collection = Mock()
        mock_collection.delete_one = AsyncMock(return_value=mock_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        result = await repo.delete_by_id("test_collection", ObjectId())

        assert result is True

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_delete_by_id_not_found(self, mock_client: Mock) -> None:
        """Test delete by ID returns False when document not found."""
        mock_result = Mock(spec=DeleteResult)
        mock_result.deleted_count = 0

        mock_collection = Mock()
        mock_collection.delete_one = AsyncMock(return_value=mock_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        result = await repo.delete_by_id("test_collection", ObjectId())

        assert result is False


class TestAsyncMongoRepositoryInsertOrUpdate:
    """Tests for insert_or_update operations."""

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_insert_or_update_inserts_new_document(
        self, mock_client: Mock
    ) -> None:
        """Test insert_or_update inserts when document doesn't exist."""
        inserted_id = ObjectId()
        mock_insert_result = Mock(spec=InsertOneResult)
        mock_insert_result.inserted_id = inserted_id
        mock_insert_result.acknowledged = True

        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=None)
        mock_collection.insert_one = AsyncMock(return_value=mock_insert_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        model = TestModel(name="Jane Doe", email="jane@example.com", age=25)
        result = await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": "jane@example.com"},
        )

        assert result == inserted_id
        mock_collection.insert_one.assert_called_once()

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_insert_or_update_updates_existing_document(
        self, mock_client: Mock
    ) -> None:
        """Test insert_or_update updates when document exists."""
        existing_id = ObjectId()
        existing_doc = {
            "_id": existing_id,
            "name": "John Doe",
            "email": "john@example.com",
        }

        mock_update_result = Mock(spec=UpdateResult)
        mock_update_result.modified_count = 1

        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=existing_doc)
        mock_collection.replace_one = AsyncMock(return_value=mock_update_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        model = TestModel(name="John Smith", email="john@example.com", age=30)
        result = await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": "john@example.com"},
        )

        assert result == existing_id
        mock_collection.replace_one.assert_called_once()

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_insert_or_update_with_on_insert_callback(
        self, mock_client: Mock
    ) -> None:
        """Test insert_or_update applies on_insert callback."""
        inserted_id = ObjectId()
        mock_insert_result = Mock(spec=InsertOneResult)
        mock_insert_result.inserted_id = inserted_id
        mock_insert_result.acknowledged = True

        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=None)
        mock_collection.insert_one = AsyncMock(return_value=mock_insert_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        def on_insert(item: TestModel) -> TestModel:
            item.age = 25  # Set default age on insert
            return item

        model = TestModel(name="John Doe", email="john@example.com")
        await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": "john@example.com"},
            on_insert=on_insert,
        )

        # Verify on_insert was applied
        call_args = mock_collection.insert_one.call_args[0][0]
        assert call_args["age"] == 25

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_insert_or_update_with_on_update_callback(
        self, mock_client: Mock
    ) -> None:
        """Test insert_or_update applies on_update callback."""
        existing_id = ObjectId()
        existing_doc = {
            "_id": existing_id,
            "name": "John Doe",
            "email": "john@example.com",
            "age": 25,
        }

        mock_update_result = Mock(spec=UpdateResult)
        mock_update_result.modified_count = 1

        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=existing_doc)
        mock_collection.replace_one = AsyncMock(return_value=mock_update_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
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
        # replace_one is called with keyword args: filter= and replacement=
        call_kwargs = mock_collection.replace_one.call_args.kwargs
        assert call_kwargs["replacement"]["age"] == 35

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_insert_or_update_no_modification(self, mock_client: Mock) -> None:
        """Test insert_or_update logs when no modification occurs."""
        existing_id = ObjectId()
        existing_doc = {
            "_id": existing_id,
            "name": "John Doe",
            "email": "john@example.com",
        }

        mock_update_result = Mock(spec=UpdateResult)
        mock_update_result.modified_count = 0  # No changes

        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=existing_doc)
        mock_collection.replace_one = AsyncMock(return_value=mock_update_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        model = TestModel(name="John Doe", email=None)
        result = await repo.insert_or_update(
            collection_name="test_collection",
            model_class=TestModel,
            item=model,
            keys={"email": None},
        )

        # Should still return the existing ID
        assert result == existing_id

    @pytest.mark.asyncio
    @patch("oidcauthlib.auth.repository.mongo.mongo_repository.AsyncMongoClient")
    async def test_insert_or_update_insert_not_acknowledged(
        self, mock_client: Mock
    ) -> None:
        """Test insert_or_update raises exception when insert is not acknowledged."""
        mock_insert_result = Mock(spec=InsertOneResult)
        mock_insert_result.acknowledged = False

        mock_collection = Mock()
        mock_collection.find_one = AsyncMock(return_value=None)
        mock_collection.insert_one = AsyncMock(return_value=mock_insert_result)

        mock_db = Mock()
        mock_db.__getitem__ = Mock(return_value=mock_collection)
        mock_client_instance = Mock()
        mock_client_instance.__getitem__ = Mock(return_value=mock_db)
        mock_client.return_value = mock_client_instance

        repo: AsyncMongoRepository[TestModel] = AsyncMongoRepository(
            server_url="mongodb://localhost:27017",
            database_name="test_db",
            username=None,
            password=None,
        )

        model = TestModel(name="John Doe", email="john@example.com")

        with pytest.raises(Exception):
            await repo.insert_or_update(
                collection_name="test_collection",
                model_class=TestModel,
                item=model,
                keys={"email": "john@example.com"},
            )


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

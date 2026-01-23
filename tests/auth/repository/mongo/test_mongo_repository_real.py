import os
import pytest
from bson import ObjectId
from typing import Optional, AsyncGenerator, Mapping, Any
from pymongo import AsyncMongoClient
from oidcauthlib.auth.repository.mongo.mongo_repository import AsyncMongoRepository
from oidcauthlib.auth.models.base_db_model import BaseDbModel

import pytest_asyncio


# Simple Pydantic model for testing
class TestModel(BaseDbModel):
    name: str
    email: Optional[str] = None
    age: Optional[int] = None


@pytest_asyncio.fixture()
async def mongo_repo() -> AsyncGenerator[AsyncMongoRepository[TestModel], None]:
    print("")
    mongo_url = os.environ.get("MONGO_URL")
    assert mongo_url is not None
    mongo_username = os.environ.get("MONGO_DB_USERNAME")
    assert mongo_username
    mongo_password = os.environ.get("MONGO_DB_PASSWORD")
    assert mongo_password
    print(f"Connecting to MongoDB at {mongo_url} with user {mongo_password}")
    db_name = "test_oidcauthlib_repo"
    client: AsyncMongoClient[Mapping[str, Any]] = AsyncMongoClient(
        mongo_url,
        username=mongo_username,
        password=mongo_password,
        readPreference="primaryPreferred",
    )
    await client.drop_database(db_name)
    repo = AsyncMongoRepository[TestModel](
        server_url=mongo_url,
        database_name=db_name,
        username=mongo_username,
        password=mongo_password,
    )
    await repo.connect()
    yield repo
    # Cleanup: drop the test database
    await client.drop_database(db_name)
    await repo.close()


@pytest.mark.asyncio
async def test_insert_and_find(mongo_repo: AsyncMongoRepository[TestModel]) -> None:
    collection = "test_collection"
    model = TestModel(name="Alice", email="alice@example.com", age=28)
    inserted_id = await mongo_repo.insert(collection, model)
    assert isinstance(inserted_id, ObjectId)
    # Find by id
    found = await mongo_repo.find_by_id(collection, TestModel, inserted_id)
    assert found is not None
    assert found.name == "Alice"
    assert found.email == "alice@example.com"
    assert found.age == 28


@pytest.mark.asyncio
async def test_update_and_delete(mongo_repo: AsyncMongoRepository[TestModel]) -> None:
    collection = "test_collection"
    model = TestModel(name="Bob", email="bob@example.com", age=35)
    inserted_id = await mongo_repo.insert(collection, model)
    # Update
    update_model = TestModel(name="Bobby", email="bob@example.com", age=36)
    updated = await mongo_repo.update_by_id(
        collection, inserted_id, update_model, TestModel
    )
    assert updated is not None
    assert updated.name == "Bobby"
    assert updated.age == 36
    # Delete
    deleted = await mongo_repo.delete_by_id(collection, inserted_id)
    assert deleted is True
    # Confirm deletion
    found = await mongo_repo.find_by_id(collection, TestModel, inserted_id)
    assert found is None


@pytest.mark.asyncio
async def test_insert_or_replace_many_insert_and_replace(
    mongo_repo: AsyncMongoRepository[TestModel],
) -> None:
    collection = "test_collection"
    # Insert two new documents
    items = [
        TestModel(name="Alice", email="alice@example.com", age=28),
        TestModel(name="Bob", email="bob@example.com", age=32),
    ]
    result = await mongo_repo.insert_or_replace_many(
        collection_name=collection,
        items=items,
        key_fields=["email"],
    )
    assert result.acknowledged
    # Query by email (key field) instead of id, since bulk_write does not update model ids
    found_alice = await mongo_repo.find_by_fields(
        collection, TestModel, {"email": "alice@example.com"}
    )
    found_bob = await mongo_repo.find_by_fields(
        collection, TestModel, {"email": "bob@example.com"}
    )
    assert found_alice is not None
    assert found_bob is not None
    assert found_alice.name == "Alice"
    assert found_bob.name == "Bob"
    assert found_alice.email == "alice@example.com"
    assert found_bob.email == "bob@example.com"
    assert found_alice.age == 28
    assert found_bob.age == 32

    # Replace Alice's document
    updated_alice = TestModel(name="Alice Updated", email="alice@example.com", age=29)
    result2 = await mongo_repo.insert_or_replace_many(
        collection_name=collection,
        items=[updated_alice],
        key_fields=["email"],
    )
    assert result2.acknowledged
    found_alice_updated = await mongo_repo.find_by_fields(
        collection, TestModel, {"email": "alice@example.com"}
    )
    assert found_alice_updated is not None
    assert found_alice_updated.name == "Alice Updated"
    assert found_alice_updated.age == 29

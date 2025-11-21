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
    if not mongo_url:
        pytest.skip("MONGO_URL environment variable not set")
    mongo_username = os.environ.get("MONGO_USERNAME")
    mongo_password = os.environ.get("MONGO_PASSWORD")
    print(f"Connecting to MongoDB at {mongo_url} with user {mongo_username}")
    db_name = "test_oidcauthlib_repo"
    client: AsyncMongoClient[Mapping[str, Any]] = AsyncMongoClient(mongo_url)
    repo = AsyncMongoRepository[TestModel](
        server_url=mongo_url,
        database_name=db_name,
        username=mongo_username,
        password=mongo_password,
        client=client,
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

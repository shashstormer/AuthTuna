import pytest
import time
from sqlalchemy import select

from authtuna.core.database import Session as DBSession, Token, SocialAccount
from authtuna.core.database import db_manager
from authtuna.core.encryption import encryption_utils


@pytest.mark.asyncio
async def test_session_is_valid_and_mismatches(auth_tuna_async):
    # Create a user and a session row directly
    user = await auth_tuna_async.users.create(
        email='sessv@example.com', username='sessv', password='ValidPassword123', ip_address='127.0.0.1'
    )
    async with db_manager.get_db() as db:
        sess = DBSession(
            session_id='s1', user_id=user.id, region='R', device='D', active=True,
            ctime=time.time(), mtime=time.time(), etime=time.time()+3600,
            e_abs_time=time.time()+86400, create_ip='127.0.0.1', last_ip='127.0.0.1',
            random_string=encryption_utils.gen_random_string(), previous_random_strings=[]
        )
        db.add(sess)
        await db.commit()
        # Valid match
        ok = await sess.is_valid(region='R', device='D', random_string=sess.random_string, db=db)
        assert ok is True
        # Region mismatch -> invalidated
        ok2 = await sess.is_valid(region='R2', device='D', random_string=sess.random_string, db=db)
        assert ok2 is False
        # Device mismatch -> invalidated
        sess.active = True
        ok3 = await sess.is_valid(region='R', device='D2', random_string=sess.random_string, db=db)
        assert ok3 is False
        # Random string mismatch -> invalidated
        sess.active = True
        ok4 = await sess.is_valid(region='R', device='D', random_string='bad', db=db)
        assert ok4 is False


@pytest.mark.asyncio
async def test_session_update_random_string_and_cookie(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email='sessrng@example.com', username='sessrng', password='ValidPassword123', ip_address='127.0.0.1'
    )
    async with db_manager.get_db() as db:
        sess = DBSession(
            session_id='s2', user_id=user.id, region='R', device='D', active=True,
            ctime=time.time(), mtime=time.time(), etime=time.time()+3600,
            e_abs_time=time.time()+86400, create_ip='127.0.0.1', last_ip='127.0.0.1',
            random_string=encryption_utils.gen_random_string(), previous_random_strings=[]
        )
        db.add(sess)
        await db.commit()
        first = sess.random_string
        new_rs = await sess.update_random_string()
        assert isinstance(new_rs, str) and new_rs != first
        # Cookie should be a JWT containing ids
        cookie = sess.get_cookie_string()
        payload = encryption_utils.decode_jwt_token(cookie)
        assert payload['session'] == sess.session_id
        assert payload['user_id'] == sess.user_id


@pytest.mark.asyncio
async def test_session_update_last_ip_and_terminate(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email='sessip@example.com', username='sessip', password='ValidPassword123', ip_address='127.0.0.1'
    )
    async with db_manager.get_db() as db:
        sess = DBSession(
            session_id='s3', user_id=user.id, region='R', device='D', active=True,
            ctime=time.time(), mtime=time.time(), etime=time.time()+3600,
            e_abs_time=time.time()+86400, create_ip='127.0.0.1', last_ip='127.0.0.1',
            random_string=encryption_utils.gen_random_string(), previous_random_strings=[]
        )
        db.add(sess)
        await db.commit()
        await sess.update_last_ip('127.0.0.2', db=db)
        assert sess.last_ip == '127.0.0.2'
        await sess.terminate('127.0.0.2', db=db)
        assert sess.active is False


@pytest.mark.asyncio
async def test_token_is_valid_and_mark_used(auth_tuna_async):
    suffix = str(int(time.time() * 1000000))
    user = await auth_tuna_async.users.create(
        email=f'tok{suffix}@example.com', username=f'tok{suffix}', password='ValidPassword123', ip_address='127.0.0.1'
    )
    token = await auth_tuna_async.tokens.create(user.id, 'email_verification')
    assert token.is_valid() is True
    async with db_manager.get_db() as db:
        await token.mark_used('127.0.0.1', db=db)
        assert token.used is True


@pytest.mark.asyncio
async def test_social_account_model_minimal(auth_tuna_async):
    suffix = str(int(time.time() * 1000000))
    user = await auth_tuna_async.users.create(
        email=f'sacc{suffix}@example.com', username=f'sacc{suffix}', password='ValidPassword123', ip_address='127.0.0.1'
    )
    async with db_manager.get_db() as db:
        sacc = SocialAccount(
            user_id=user.id, provider='google', provider_user_id='gid', token_type='bearer', access_token='at'
        )
        db.add(sacc)
        await db.commit()
        # Fetch back to ensure persistence
        row = (await db.execute(select(SocialAccount))).scalars().first()
        assert row is not None and row.provider == 'google'

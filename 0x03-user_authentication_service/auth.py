#!/usr/bin/env python3
"""The Authentication Module"""

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from user import User
from uuid import uuid4


def _hash_password(password: str) -> str:
    """Returning a salted hash on input password """
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed


def _generate_uuid() -> str:
    """Returning a string representation of a new UUID"""
    UUID = uuid4()
    return str(UUID)


class Auth:
    """Auth class interacting with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """This registers a user in the database and
        Returns: User Object
        """

        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)

            return user

        else:
            raise ValueError(f'User {email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        """If password is valid returns true, elsefalse"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_password = user.hashed_password
        encoded_password = password.encode()

        if bcrypt.checkpw(encoded_password, user_password):
            return True

        return False

    def create_session(self, email: str) -> str:
        """Returning the session ID for a user"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()

        self._db.update_user(user.id, session_id=session_id)

        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[str, None]:
        """This takes a single session_id string argument and
        Returns a string or None
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """Updating the corresponding user(s) session ID to None"""
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None

        self._db.update_user(user.id, session_id=None)

        return None

    def get_reset_password_token(self, email: str) -> str:
        """Generating/reset password token if the user exists"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()

        self._db.update_user(user.id, reset_token=reset_token)

        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """This uses reset token to validate update of users password
        """
        if reset_token is None or password is None:
            return None

        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        hashed_password = _hash_password(password)
        self._db.update_user(user.id,
                             hashed_password=hashed_password,
                             reset_token=None)

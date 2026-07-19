from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity

from app.models.group import GroupMembership


def group_member_required(fn):
    @wraps(fn)
    def wrapper(group_id, *args, **kwargs):
        user_id = int(get_jwt_identity())
        membership = GroupMembership.query.filter_by(group_id=group_id, user_id=user_id).first()
        if not membership:
            return jsonify({"error": "You are not a member of this group"}), 403
        return fn(group_id, *args, **kwargs)
    return wrapper


def group_owner_required(fn):
    @wraps(fn)
    def wrapper(group_id, *args, **kwargs):
        user_id = int(get_jwt_identity())
        membership = GroupMembership.query.filter_by(group_id=group_id, user_id=user_id).first()
        if not membership or membership.role != "owner":
            return jsonify({"error": "Only the group owner can do this"}), 403
        return fn(group_id, *args, **kwargs)
    return wrapper